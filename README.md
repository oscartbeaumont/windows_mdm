# Windows MDM Demo

This project is a super simple and minimal implementation of the device enrollment and management protocols for using Windows 10 MDM. This project is designed to act as a starting place for your own projects with the protocols. DO NOT use this code as a reference for a production server as it designed to be a minimal starting place. I highly recommend using [Mattrax](https://github.com/mattrax/Mattrax) if you are managing production devices as mistakes in the implementation could cause security incidents or major outages. The server uses 'Federated' (default and required for AzureAD) or 'OnPremise' authentication and doesn't currently support 'Certificate' authentication. This project uses the protocols:

- [MD-MDE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mde/d9e18701-cd4c-4fdb-8a3e-c1ddd33b1307)
- [MS-MDM](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/33769a92-ac31-47ef-ae7b-dc8501f7104f)
- Some of [MS-WSTEP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/4766a85d-0d18-4fa1-a51f-e5cb98b752ea) & Some of [MS-XCEP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/08ec4475-32c2-457d-8c27-5a176660a210)

## Licence

This code is MIT licensed so use it in your projects as long as you credit to me. Please also give me credit if this project helped you in understanding the protocol to build your server. If this helps reach out I would love to hear how you are using it.

## Usage

Once you have [Go Lang](https://golang.org) and Git installed use the following unix commands.

```bash
git clone https://github.com/oscartbeaumont/windows_mdm.git
cd windows_mdm/
go run patch/patch.go # This changes the Go Lang standard library to support extra characters in certificates to remove the "asn1: syntax error: PrintableString contains invalid character" error.
# Put your webserver's HTTPS certificate in './certs/certificate.pem' & the private key in './certs/privatekey.pem'
# This HTTPS certificate must be valid and contain both the primary domain and the enterpriseenrollment subdomain/s (These should match the email of your users)
# Eg. Containing the domains 'mdm.otbeaumont.me' & 'enterpriseenrollment.otbeaumont.me' results in '*@otbeaumont.me' being able to enroll. Adding an extra 'enterpriseenrollment.student.otbeaumont.me' would then allow '*@otbeaumont.me' & '*@student.otbeaumont.me' to be able to enroll.
go run ./ --domain=mdm.example.com --dl-user-email=test@example.com --auth-policy=Federated # Replace the domains to match your environment
# Server is now running and listening on port 443 (unless an error is throw)
```

## Enrolling a Device

There are 3 main methods of enrolling a device into management:

1. Deeplink (A special url that initiates enrollment)
2. Through the Settings menu (Enter an email and the server is discovered)
3. AzureAD (upon joining a device the MDM is also enrolled)

I reccomend manually enrolling the device for development because the Deeplink, at least on my device, stops working if you use it lots of time on the same device without restarting your broswer and AzureAD adds unnneded development complexity (obviously if your developing AzureAD features you will need to use it).

### Deeplink

The end user goes to the url (in this case your primary domain with the path '/deeplink') and the MDM enrollment begins. This link could be included in an email or company portal website to make enrollment really easy for the end user. This initiates the same process as manually beginning enrollment through the settings menu.

### Manually

On a Windows 10 machine go to "Settings" > "Accounts" > "Access work or school" > "Connect" > Enter your email and the enrollment process will begin.

### AzureAD

Start by adding a custom MDM server to AzureAD. This can be done by clicking "Mobility (MDM and MAM)" in the sidebar, then "On-premises MDM application" and set the name as you wish and click "Add". Next you need to tell it where your MDM server is by going into its setttings page from "Mobility (MDM and MAM)" in the sidebar, then set the ToS url to 'https://example.com/EnrollmentServer/ToS' and the discovery URL to 'https://example.com/EnrollmentServer/Discovery.svc'. You will also need to set a scope for which AzureAD users the MDM will be installed for. Obviously replace example.com with your servers primary domain (as set by the command line flag). Finally you have to configure its application by clicking "On-premises MDM application settings" at the bottom of the MDM servers settings page then setting the below settings.

- "Expose an API" > "Application ID URI" > "Edit" > Set it to your servers primary domain
- "API Permissions" > "Grant admin concent for {Directory Name}" > Login with a admin user user IN THE directory > "Accept"
- "Authentication" > Add a new one of type "Web" and the redirect URI as the servers primary domain (This may not be required, I havn't checked)

## Help

If you have questions about this project or the protocol in general, feel free to contact me [here](https://otbeaumont.me/contact) but please try and work it out yourself before contacting me. This is a working project (which is way more than what I had when I started) and this protocol requires heaps of trial and error to get anywhere so get used to it.
