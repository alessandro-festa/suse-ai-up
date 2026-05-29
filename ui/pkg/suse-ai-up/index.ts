import { importTypes } from '@rancher/auto-import';
import type { IPlugin } from '@shell/core/types';
import routes from './routing';
import * as productModule from './product';
import './styles/tokens.scss';

// SUSE AI Up Rancher Dashboard extension entry.
export default function(plugin: IPlugin): void {
  importTypes(plugin);

  plugin.metadata = {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    ...require('./package.json'),
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    icon: require('./assets/logo-icon.svg'),
  };

  plugin.addProduct(productModule as any);
  plugin.addRoutes(routes);
}
