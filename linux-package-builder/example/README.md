# MyApp Example

This is a simple example application to demonstrate the Linux Package Builder.

## Files

- `bin/myapp`: The main application script
- `config/myapp.conf`: Configuration file
- `data/sample.txt`: Sample data file

## Building Packages

To build packages for this example application:

1. Copy the files to the appropriate locations:

```bash
cp -r example/bin/* /path/to/your/app/bin/
cp -r example/config/* /path/to/your/app/config/
cp -r example/data/* /path/to/your/app/data/
```

2. Edit the configuration file in `config/package.yml` to match your requirements.

3. Run the build script:

```bash
cd linux-package-builder
./build.sh -v 1.0.0
```

4. Test the built packages:

```bash
./test.sh
```

## Usage

Once installed, the application can be run with:

```bash
myapp
```

Or with a custom configuration file:

```bash
myapp --config /path/to/custom/config.conf
``` 