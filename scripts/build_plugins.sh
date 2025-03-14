#!/bin/bash

# Script to build and install plugins for Elemta

# Set variables
PLUGIN_DIR="./plugins"
EXAMPLES_DIR="./examples/plugins"
PLUGIN_TYPES=("antivirus" "antispam")

# Create plugin directory if it doesn't exist
mkdir -p "$PLUGIN_DIR"

# Function to build a plugin
build_plugin() {
    local plugin_type=$1
    local plugin_name=$2
    local plugin_file="${EXAMPLES_DIR}/${plugin_name}.go"
    local plugin_output="${PLUGIN_DIR}/${plugin_name}.so"

    echo "Building ${plugin_type} plugin: ${plugin_name}"
    
    if [ ! -f "$plugin_file" ]; then
        echo "Error: Plugin file not found: $plugin_file"
        return 1
    fi

    go build -buildmode=plugin -o "$plugin_output" "$plugin_file"
    
    if [ $? -eq 0 ]; then
        echo "Successfully built plugin: $plugin_output"
    else
        echo "Error: Failed to build plugin: $plugin_name"
        return 1
    fi
}

# Function to build all plugins of a specific type
build_plugins_of_type() {
    local plugin_type=$1
    local pattern="${EXAMPLES_DIR}/example_${plugin_type}*.go"
    
    echo "Building all ${plugin_type} plugins..."
    
    for plugin_file in $pattern; do
        if [ -f "$plugin_file" ]; then
            local plugin_name=$(basename "$plugin_file" .go)
            build_plugin "$plugin_type" "$plugin_name"
        fi
    done
}

# Function to build all plugins
build_all_plugins() {
    echo "Building all plugins..."
    
    for plugin_type in "${PLUGIN_TYPES[@]}"; do
        build_plugins_of_type "$plugin_type"
    done
}

# Function to clean all plugins
clean_plugins() {
    echo "Cleaning all plugins..."
    rm -f "${PLUGIN_DIR}"/*.so
    echo "All plugins cleaned."
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTION]"
    echo "Build and install plugins for Elemta."
    echo ""
    echo "Options:"
    echo "  -a, --all                Build all plugins"
    echo "  -c, --clean              Clean all plugins"
    echo "  -h, --help               Show this help message"
    echo "  -t, --type TYPE          Build all plugins of a specific type (antivirus, antispam)"
    echo "  -p, --plugin PLUGIN      Build a specific plugin"
    echo ""
    echo "Examples:"
    echo "  $0 --all                 Build all plugins"
    echo "  $0 --type antivirus      Build all antivirus plugins"
    echo "  $0 --plugin example_antivirus  Build a specific plugin"
    echo "  $0 --clean               Clean all plugins"
}

# Parse command line arguments
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        -a|--all)
            build_all_plugins
            shift
            ;;
        -c|--clean)
            clean_plugins
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -t|--type)
            if [ -z "$2" ]; then
                echo "Error: No plugin type specified."
                exit 1
            fi
            
            if [[ ! " ${PLUGIN_TYPES[@]} " =~ " $2 " ]]; then
                echo "Error: Invalid plugin type: $2"
                echo "Valid types are: ${PLUGIN_TYPES[@]}"
                exit 1
            fi
            
            build_plugins_of_type "$2"
            shift 2
            ;;
        -p|--plugin)
            if [ -z "$2" ]; then
                echo "Error: No plugin name specified."
                exit 1
            fi
            
            # Determine plugin type from name
            if [[ "$2" == *"antivirus"* ]]; then
                build_plugin "antivirus" "$2"
            elif [[ "$2" == *"antispam"* ]]; then
                build_plugin "antispam" "$2"
            else
                echo "Error: Unable to determine plugin type from name: $2"
                exit 1
            fi
            
            shift 2
            ;;
        *)
            echo "Error: Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

exit 0 