import 'fluent-intl-polyfill/compat';
import { MessageContext } from 'fluent/compat';
import { DOMLocalization } from 'fluent-dom/compat';

// eslint-disable-next-line @elastic/kibana-custom/no-default-export
export default function (chrome, internals) {
  const context = new MessageContext('en-US', {
    functions: {
      DURATION: (arg) => arg + ' { mb }'
    }
  });
  context.addMessages(internals.translations || '');

  const getMessages = function* () { yield context; };
  const l10n = new DOMLocalization(window, [], getMessages);

  chrome.i18n = {
    async init() {
      l10n.connectRoot(document.documentElement);
      await l10n.translateRoots();
    },

    getMessages,

    t(l10nId, args) {
      return context.format(context.getMessage(l10nId), args);
    }
  };

  /**
   * ui/chrome Translations API
   *
   *   Translations
   *     Returns the translations which have been loaded by the Kibana server instance
   */

  /**
   * @return {Object} - Translations
   */
  chrome.getTranslations = function () {
    return internals.translations || [];
  };
}
