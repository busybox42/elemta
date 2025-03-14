# Plugin System

Elemta includes a plugin system that allows you to extend its functionality with custom plugins. This document provides an overview of the plugin system and how to create and use plugins.

## Overview

The plugin system in Elemta is based on Go's plugin package, which allows for dynamic loading of Go code at runtime. Plugins can be used to add new antivirus or antispam scanners, or to implement custom processing logic.

## Plugin Types

Elemta supports two types of plugins:

- **Antivirus Plugins**: Implement the `AntivirusPlugin` interface to add custom virus scanning capabilities.
- **Antispam Plugins**: Implement the `AntispamPlugin` interface to add custom spam detection capabilities.

## Plugin Interfaces

### AntivirusPlugin Interface

```go
type AntivirusPlugin interface {
    GetScanner() antivirus.Scanner
    GetInfo() *PluginInfo
}
```

### AntispamPlugin Interface

```go
type AntispamPlugin interface {
    GetScanner() antispam.Scanner
    GetInfo() *PluginInfo
}
```

### PluginInfo Struct

```go
type PluginInfo struct {
    Name        string
    Version     string
    Description string
    Author      string
}
```

## Creating Plugins

To create a plugin, you need to implement the appropriate plugin interface and export it as a Go plugin. Here's a step-by-step guide:

1. Create a new Go file for your plugin.
2. Import the necessary packages:
   ```go
   import (
       "github.com/busybox42/elemta/internal/antivirus" // or antispam
       "github.com/busybox42/elemta/internal/plugin"
   )
   ```
3. Implement the scanner interface (either `antivirus.Scanner` or `antispam.Scanner`).
4. Create a plugin struct that implements the plugin interface.
5. Export the plugin as a variable named `AntivirusPlugin` or `AntispamPlugin`.
6. Build the plugin with `go build -buildmode=plugin`.

## Example Plugins

Elemta includes example plugins in the `examples/plugins` directory:

- `example_antivirus.go`: An example antivirus plugin.
- `example_antispam.go`: An example antispam plugin.

You can use these examples as a starting point for your own plugins.

## Building Plugins

To build the example plugins, you can use the provided Makefile:

```bash
cd examples/plugins
make
```

This will build the example plugins and place them in the `plugins` directory.

## Configuring Plugins

Plugins can be configured in the Elemta configuration file:

```json
{
  "plugins": {
    "enabled": true,
    "plugin_path": "./plugins",
    "plugins": ["example_antivirus", "example_antispam"]
  }
}
```

- `enabled`: Whether to enable the plugin system.
- `plugin_path`: The directory where plugins are located.
- `plugins`: A list of plugins to load.

## Plugin Loading

When Elemta starts, it will load all plugins specified in the configuration file. If a plugin fails to load, Elemta will log an error but continue loading other plugins.

## Plugin API

Plugins can access the following APIs:

- `antivirus.Scanner`: Interface for antivirus scanners.
- `antispam.Scanner`: Interface for antispam scanners.
- `plugin.AntivirusPlugin`: Interface for antivirus plugins.
- `plugin.AntispamPlugin`: Interface for antispam plugins.
- `plugin.PluginInfo`: Struct for plugin information.
- `plugin.AntivirusPluginBase`: Base implementation of the `AntivirusPlugin` interface.
- `plugin.AntispamPluginBase`: Base implementation of the `AntispamPlugin` interface.

## Best Practices

- Keep plugins simple and focused on a single task.
- Use the base implementations (`AntivirusPluginBase` and `AntispamPluginBase`) to simplify plugin creation.
- Handle errors gracefully and provide meaningful error messages.
- Document your plugins with comments and README files.
- Test your plugins thoroughly before deploying them in production.

## Troubleshooting

If you encounter issues with plugins, check the following:

- Make sure the plugin is built with the same Go version as Elemta.
- Check that the plugin is in the correct directory.
- Verify that the plugin is specified in the configuration file.
- Look for error messages in the Elemta logs.
- Try building and loading the example plugins to verify that the plugin system is working correctly. 