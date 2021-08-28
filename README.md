# Interactsh Collaborator
This is a Burpsuite plugin for Interact.sh

This plugin implements the client side logic from [interactsh-client](https://github.com/projectdiscovery/interactsh/). It will allow you to generate new domains that can be used for OOB testing.

This extension works in addition to Burpsuite's Collaborator service.

All results are logged in the Interactsh tab once the extension is loaded. Verbose details will be displayed in the bottom window once an OOB interaction is logged and clicked on.

### Build

1. `mvn package`
2. Add the target/collaborator-1.0.0-dev-jar-with-dependencies.jar file as a new Java extension in Burpsuite

Alternatively you can download the precompiled library from the [latest releast](https://github.com/wdahlenburg/interactsh-collaborator/releases/latest)

### Usage

After the extension is installed you should be able to see the Interactsh tab. Navigate to the tab and click "Generate Interactsh Url".

This button will copy the generated domain name to your clipboard. The domain name will also be logged to the extension output.

You can then use this domain name in any OOB testing. To generate a sample event you can visit that domain in a new browser tab.

Data should populate after a few seconds into the table with details about what type of OOB interaction occurred.
