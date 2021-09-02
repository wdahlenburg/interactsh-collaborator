# Interactsh Collaborator
This is a Burpsuite plugin for Interact.sh

This plugin implements the client side logic from [interactsh-client](https://github.com/projectdiscovery/interactsh/). It will allow you to generate new domains that can be used for OOB testing. If you host your own version of Interactsh you can configure it in the Configuration tab.

This extension works in addition to Burpsuite's Collaborator service.

All results are logged in the Interactsh Logs tab once the extension is loaded. Verbose details will be displayed in the bottom window once an OOB interaction is logged and selected.

![Interactsh-Collaborator](https://user-images.githubusercontent.com/4451504/131763193-7f0c32f3-1683-4166-9c9d-1a948ea04fd4.gif)

### Build

1. `mvn package`
2. Add the target/collaborator-1.x.x-dev-jar-with-dependencies.jar file as a new Java extension in Burpsuite

Alternatively you can download the precompiled library from the [latest releast](https://github.com/wdahlenburg/interactsh-collaborator/releases/latest)

### Usage

After the extension is installed you should be able to see the Interactsh tab. Navigate to the tab and click the button labeled `Generate Interactsh Url`.


This button will copy the generated domain name to your clipboard. The domain name will also be logged to the extension output.


You can then use this domain name in any OOB testing. To generate a sample event you can visit that domain in a new browser tab.


Data should populate after a few seconds into the table with details about what type of OOB interaction occurred.


Try adjusting the poll time to a shorter value when you expect active results.
