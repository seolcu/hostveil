package scan

import "encoding/json"

// _jsonMarshal is the implementation of stdJSONMarshal; it is
// isolated here so the orchestrator file doesn't pull the encoding/json
// import into a tighter dependency surface.
var _jsonMarshal = json.Marshal
