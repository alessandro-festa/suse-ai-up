package bootstrap

import (
	"context"
	"log"
	"os"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/SUSE/suse-ai-up/internal/config"
	"github.com/SUSE/suse-ai-up/internal/handlers"
	"github.com/SUSE/suse-ai-up/pkg/auth"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/logging"
	"github.com/SUSE/suse-ai-up/pkg/mcp"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/plugins"
	"github.com/SUSE/suse-ai-up/pkg/proxy"
	"github.com/SUSE/suse-ai-up/pkg/scanner"
	"github.com/SUSE/suse-ai-up/pkg/services"
	adaptersvc "github.com/SUSE/suse-ai-up/pkg/services/adapters"
	authsvc "github.com/SUSE/suse-ai-up/pkg/services/auth"
	registryadmin "github.com/SUSE/suse-ai-up/pkg/services/registry/admin"
	registryloader "github.com/SUSE/suse-ai-up/pkg/services/registry/loader"
	"github.com/SUSE/suse-ai-up/pkg/session"
)

// AppServices holds every wired component the proxy needs at runtime.
// Bootstrap returns one of these; the router and main consume it.
type AppServices struct {
	Cfg *config.Config

	AdapterStore       clients.AdapterResourceStore
	RegistryStore      clients.MCPServerStore
	UserStore          clients.UserStore
	GroupStore         clients.GroupStore
	SessionStore       session.SessionStore
	TokenManager       *auth.TokenManager
	UserGroupService   *services.UserGroupService
	UserAuthService    *auth.UserAuthService
	StdioToHTTPAdapter *proxy.StdioToHTTPAdapter
	RemoteHTTPPlugin   *proxy.RemoteHttpProxyPlugin
	SidecarManager     *proxy.SidecarManager
	K8sClient          kubernetes.Interface
	RegistryManager    *handlers.DefaultRegistryManager
	AdapterService     *adaptersvc.AdapterService
	ServiceManager     *plugins.ServiceManager

	DiscoveryHandler       *handlers.DiscoveryHandler
	TokenHandler           *handlers.TokenHandler
	MCPAuthHandler         *handlers.MCPAuthHandler
	RegistryHandler        *handlers.RegistryHandler
	AdapterHandler         *handlers.AdapterHandler
	UserGroupHandler       *handlers.UserGroupHandler
	AuthHandler            *handlers.AuthHandler
	RouteAssignmentHandler *handlers.RouteAssignmentHandler
	PluginHandler          *handlers.PluginHandler
}

// SharedStores carries store instances the caller owns and wants the
// bootstrap layer to reuse instead of constructing fresh ones. Each field
// is optional; nil means bootstrap falls back to its default (file- or
// in-memory-backed). P2.4/PR2 added PluginServiceManager; P2.4/PR3 added
// the auth.* projections so HTTP read endpoints (GET /users, /groups)
// see CR-reconciled state. Writes and Authenticate stay on the local
// file store — unifying those requires User CR credentialSecretRef
// support, which is a follow-up post Epic 1.
type SharedStores struct {
	MCPServerStore       clients.MCPServerStore
	PluginServiceManager *plugins.ServiceManager
	UserStore            authsvc.UserStore
	GroupStore           authsvc.GroupStore
}

// BootstrapWithStores wires the proxy with caller-provided stores swapped
// in for the bootstrap-default ones. Used by cmd/manager to make the HTTP
// handlers and the reconcilers see the same in-process state.
func BootstrapWithStores(ctx context.Context, cfg *config.Config, shared SharedStores) (*AppServices, error) {
	if cfg.OtelEnabled {
		if err := initOTEL(ctx, cfg); err != nil {
			log.Printf("Failed to initialize OpenTelemetry: %v", err)
			// Continue without OTEL rather than failing
		}
	}

	stores := clients.New(clients.StoreConfig{})
	if shared.MCPServerStore != nil {
		stores.Registry = shared.MCPServerStore
	}
	adapterStore := stores.Adapter
	tokenManager, err := auth.NewTokenManager("mcp-gateway")
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}

	// fileUserStore/fileGroupStore are the legacy in-memory stores used
	// by UserAuthService (writes + Authenticate). userStore/groupStore
	// are what UserGroupService sees: layered over the auth.* projection
	// when the caller supplied it, so reconciled User/Group CRs are
	// visible to GET /users and GET /groups without touching the
	// password-aware auth path.
	fileUserStore := stores.User
	fileGroupStore := stores.Group
	var userStore clients.UserStore = fileUserStore
	if shared.UserStore != nil {
		userStore = newLayeredUserStore(fileUserStore, shared.UserStore)
	}
	var groupStore clients.GroupStore = fileGroupStore
	if shared.GroupStore != nil {
		groupStore = newLayeredGroupStore(fileGroupStore, shared.GroupStore)
	}
	userGroupService := services.NewUserGroupService(userStore, groupStore)

	userAuthConfig := &models.UserAuthConfig{
		Mode:    cfg.AuthMode,
		DevMode: cfg.DevMode,
		Local: &models.LocalAuthConfig{
			DefaultAdminPassword: cfg.AdminPassword,
			ForcePasswordChange:  cfg.ForcePasswordChange,
			PasswordMinLength:    cfg.PasswordMinLength,
		},
		GitHub: &models.GitHubAuthConfig{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURI:  cfg.GitHubRedirectURI,
			AllowedOrgs:  cfg.GitHubAllowedOrgs,
			AdminTeams:   cfg.GitHubAdminTeams,
		},
		Rancher: &models.RancherAuthConfig{
			IssuerURL:     cfg.RancherIssuerURL,
			ClientID:      cfg.RancherClientID,
			ClientSecret:  cfg.RancherClientSecret,
			RedirectURI:   cfg.RancherRedirectURI,
			AdminGroups:   cfg.RancherAdminGroups,
			FallbackLocal: cfg.RancherFallbackLocal,
		},
	}

	// UserAuthService stays on fileUserStore (not the layered one).
	// CR-projected RegisteredUser carries no PasswordHash, so wiring
	// UserAuthService through the projection would either break local
	// auth or force every login to short-circuit to the file fallback.
	// Keeping the bare store makes the deferral explicit and unifies
	// only when the User CR credentialSecretRef story lands.
	userAuthService := auth.NewUserAuthService(fileUserStore, tokenManager, userAuthConfig)

	log.Printf("DEBUG: CreateInitialGroups: %v, Groups count: %d", cfg.CreateInitialGroups, len(cfg.InitialGroups))
	if cfg.CreateInitialGroups {
		log.Printf("DEBUG: Creating %d initial groups", len(cfg.InitialGroups))
		for _, initialGroup := range cfg.InitialGroups {
			log.Printf("Processing group: %s", initialGroup.ID)
			group := models.Group{
				ID:          initialGroup.ID,
				Name:        initialGroup.Name,
				Description: initialGroup.Description,
				Permissions: strings.Split(initialGroup.Permissions, ","),
			}
			if err := userGroupService.CreateGroup(context.Background(), group); err != nil {
				log.Printf("Note: Could not create initial group %s: %v", initialGroup.ID, err)
			} else {
				log.Printf("Created initial group: %s", initialGroup.ID)
			}
		}
	} else {
		log.Printf("CreateInitialGroups is disabled")
	}

	log.Printf("DEBUG: CreateInitialUsers: %v, Users count: %d", cfg.CreateInitialUsers, len(cfg.InitialUsers))
	if cfg.CreateInitialUsers {
		log.Printf("DEBUG: Creating %d initial users", len(cfg.InitialUsers))
		for _, initialUser := range cfg.InitialUsers {
			log.Printf("Processing user: %s", initialUser.ID)
			user := models.User{
				ID:           initialUser.ID,
				Name:         initialUser.Name,
				Email:        initialUser.Email,
				Groups:       strings.Split(initialUser.Groups, ","),
				AuthProvider: initialUser.AuthProvider,
			}

			password := initialUser.Password
			if password == "" && initialUser.AuthProvider == string(models.UserAuthProviderLocal) {
				password = cfg.AdminPassword
			}

			if _, err := userGroupService.GetUser(context.Background(), initialUser.ID); err != nil {
				if err := userAuthService.CreateUser(context.Background(), user, password); err != nil {
					log.Printf("Warning: Failed to create initial user %s: %v", initialUser.ID, err)
				} else {
					log.Printf("Created initial user: %s", initialUser.ID)
				}
			} else {
				log.Printf("User %s already exists", initialUser.ID)
			}
		}
	} else {
		log.Printf("CreateInitialUsers is disabled")
	}

	capabilityCache := mcp.NewCapabilityCache()
	cache := mcp.NewMCPCache(nil)
	monitor := mcp.NewMCPMonitor(nil)
	sessionStore := session.NewInMemorySessionStore()
	protocolHandler := mcp.NewProtocolHandler(sessionStore, capabilityCache)
	messageRouter := mcp.NewMessageRouter(protocolHandler, sessionStore, capabilityCache, cache, monitor)

	stdioProxy := proxy.NewLocalStdioProxyPlugin()
	log.Printf("stdioProxy initialized: %v", stdioProxy != nil)

	stdioToHTTPAdapter := proxy.NewStdioToHTTPAdapter(stdioProxy, messageRouter, sessionStore, protocolHandler, capabilityCache)
	log.Printf("stdioToHTTPAdapter initialized: %v", stdioToHTTPAdapter != nil)

	remoteHTTPAdapter := proxy.NewRemoteHTTPProxyAdapter(sessionStore, messageRouter, protocolHandler, capabilityCache)
	log.Printf("remoteHTTPAdapter initialized: %v", remoteHTTPAdapter != nil)
	_ = remoteHTTPAdapter

	remoteHTTPPlugin := proxy.NewRemoteHttpProxyPlugin()
	log.Printf("remoteHTTPPlugin initialized: %v", remoteHTTPPlugin != nil)

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("Failed to get in-cluster config, trying kubeconfig: %v", err)
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			log.Printf("Failed to get Kubernetes config: %v", err)
			log.Printf("Sidecar functionality will not be available")
		}
	}

	var sidecarManager *proxy.SidecarManager
	if kubeConfig != nil {
		kubeClient, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			log.Printf("Failed to create Kubernetes client: %v", err)
		} else {
			sidecarManager = proxy.NewSidecarManager(kubeClient, "default")
			log.Printf("SidecarManager initialized successfully")
		}
	}

	scanConfig := &models.ScanConfig{
		ScanRanges:    []string{"192.168.1.0/24"},
		Ports:         []string{"8000", "8001", "9000"},
		Timeout:       "30s",
		MaxConcurrent: 10,
		ExcludeProxy:  func() *bool { b := true; return &b }(),
	}
	networkScanner := scanner.NewNetworkScanner(scanConfig)
	discoveryStore := scanner.NewInMemoryDiscoveryStore()
	scanManager := scanner.NewScanManager(networkScanner, discoveryStore)
	discoveryHandler := handlers.NewDiscoveryHandler(scanManager, discoveryStore)
	tokenHandler := handlers.NewTokenHandler(adapterStore, tokenManager)
	mcpAuthHandler := handlers.NewMCPAuthHandler(adapterStore, nil)

	registryStore := stores.Registry
	registryManager := handlers.NewDefaultRegistryManager(registryStore)

	logging.ProxyLogger.Info("Initializing AdapterService with SidecarManager")
	adapterService := adaptersvc.NewAdapterService(adapterStore, registryStore, sidecarManager)
	logging.ProxyLogger.Info("AdapterService created: %v", adapterService != nil)
	adapterHandler := handlers.NewAdapterHandler(adapterService, userGroupService)
	logging.ProxyLogger.Info("AdapterHandler created: %v", adapterHandler != nil)
	logging.ProxyLogger.Success("AdapterService and AdapterHandler initialized")

	if err := registryloader.LoadInitialRegistry(ctx, registryManager, cfg); err != nil {
		log.Printf("Warning: initial registry load returned error: %v", err)
	}

	var k8sClient kubernetes.Interface
	if config, err := rest.InClusterConfig(); err == nil {
		k8sClient, _ = kubernetes.NewForConfig(config)
		log.Printf("Kubernetes client initialized for ConfigMap updates")
	} else {
		log.Printf("Not running in Kubernetes cluster, ConfigMap updates disabled")
	}

	registryAdminSvc := registryadmin.NewService(registryStore, registryManager, k8sClient, cfg)
	registryHandler := handlers.NewRegistryHandler(registryStore, registryManager, adapterStore, userGroupService, cfg, k8sClient, registryAdminSvc)

	userGroupHandler := handlers.NewUserGroupHandler(userGroupService)
	authHandler := handlers.NewAuthHandler(userAuthService)
	routeAssignmentHandler := handlers.NewRouteAssignmentHandler(userGroupService, registryStore)
	logging.ProxyLogger.Info("UserGroupHandler created: %v", userGroupHandler != nil)
	logging.ProxyLogger.Info("RouteAssignmentHandler created: %v", routeAssignmentHandler != nil)

	serviceManager := shared.PluginServiceManager
	if serviceManager == nil {
		serviceManager = plugins.NewServiceManager(cfg, registryManager)
	}
	pluginHandler := handlers.NewPluginHandler(serviceManager)

	return &AppServices{
		Cfg:                    cfg,
		AdapterStore:           adapterStore,
		RegistryStore:          registryStore,
		UserStore:              userStore,
		GroupStore:             groupStore,
		SessionStore:           sessionStore,
		TokenManager:           tokenManager,
		UserGroupService:       userGroupService,
		UserAuthService:        userAuthService,
		StdioToHTTPAdapter:     stdioToHTTPAdapter,
		RemoteHTTPPlugin:       remoteHTTPPlugin,
		SidecarManager:         sidecarManager,
		K8sClient:              k8sClient,
		RegistryManager:        registryManager,
		AdapterService:         adapterService,
		ServiceManager:         serviceManager,
		DiscoveryHandler:       discoveryHandler,
		TokenHandler:           tokenHandler,
		MCPAuthHandler:         mcpAuthHandler,
		RegistryHandler:        registryHandler,
		AdapterHandler:         adapterHandler,
		UserGroupHandler:       userGroupHandler,
		AuthHandler:            authHandler,
		RouteAssignmentHandler: routeAssignmentHandler,
		PluginHandler:          pluginHandler,
	}, nil
}
