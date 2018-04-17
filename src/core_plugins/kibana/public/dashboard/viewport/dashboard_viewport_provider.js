import React from 'react';
import PropTypes from 'prop-types';
import { store } from '../../store';
import { Provider } from 'react-redux';
import { DashboardViewportContainer } from './dashboard_viewport_container';
import chrome from 'ui/chrome';
import { LocalizationProvider } from 'fluent-react/compat';

export function DashboardViewportProvider(props) {
  return (
    <LocalizationProvider messages={chrome.i18n.getMessages()}>
      <Provider store={store}>
        <DashboardViewportContainer {...props} />
      </Provider>
    </LocalizationProvider>
  );
}

DashboardViewportProvider.propTypes = {
  getEmbeddableFactory: PropTypes.func.isRequired,
};
