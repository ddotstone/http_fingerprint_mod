# Define your module name and source file
MODULE_NAME = mod_http_fingerprint_log
SRC = mod_http_fingerprint_log.c

# Apache module directories (adjust paths if necessary)
APACHE_LIB_DIR = /usr/lib/apache2/modules
APACHE_CONF_DIR = /etc/apache2/mods-available

# Compiler and apxs2 path
APXS = apxs2

# Targets
all: build

# Build the module using apxs2
build:
	$(APXS) -iac $(SRC)

# Clean the module (optional, if you want to clean up after build)
clean:
	$(APXS) -c $(SRC)
	rm -f $(MODULE_NAME).so

# Install the module (this step is handled by -i flag, but can be separated if needed)
install:
	$(APXS) -i -a -c $(SRC)

# Uninstall the module (optional)
uninstall:
	$(APXS) -q -n $(MODULE_NAME) uninstall

.PHONY: all build clean install uninstall