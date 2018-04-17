exit-full-screen = Exit full screen!
exit-full-screen-mode =
  .aria-label = Exit full screen mode!
dashboard-title = Kibana Dashboard
    .title = Your best dashboard
UI-WELCOME_MESSAGE = {-mega} Loading Kibana { DATETIME($date, month: "long", year: "numeric", hour: "numeric") } and { NUMBER($ratio, style: "currency", currencyDisplay: "symbol", currency: "USD") } and { DURATION($ratio) }
UI-WELCOME_ERROR = Kibana did not load properly. Check the server output for more information.
discover-hits =
  { $count ->
      [one] hit
      *[other] hits
  }
time-range-tooltip = {-mega} От меня To change the time, click the clock icon in the navigation bar
discovery-description = От меня Interactively explore your data by querying and filtering raw documents.
