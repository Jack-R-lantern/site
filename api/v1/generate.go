package bpf

//go:generate go tool oapi-codegen -config models-cfg.yaml ./oas-components.yaml
//go:generate go tool oapi-codegen -config server-cfg.yaml ./oas-api.yaml
//go:generate go tool oapi-codegen -config client-cfg.yaml ./oas-api.yaml
