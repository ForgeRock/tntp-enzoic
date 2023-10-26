# Enzoic Auth Tree Node

## Enzoic

Enzoic specializes in cyber-security and fraud detection
Cybersecurity is a complex and ever-evolving market. Compromised credentials remain a large risk for most organizations and the attackers are getting more sophisticated each year.

Organizations need solutions that combine cloud security expertise and innovative, easy-to-deploy tools to layer-in with other security measures.

Enzoic was created as a streamlined solution to detect compromised credentials with minimal friction for end users.

## Installation

The Enzoic-Auth tree nodes are packaged as a jar file and the latest release can be download [here](https://github.com/Enzoic/forgerock/releases/latest).
 Once downloaded, copy the jar file to the ../web-container/webapps/openam/WEB-INF/lib

## Enzoic Auth Tree Configuration

Below are the nodes that will be available after deploying the jar file:

### Enzoic Check Compromised Password
This node will check compromised password using enzoic java client.

Configuration is:
* API Key : API Key to call enzoic api.
* Secret : Secret to call enzoic api
* Synchronous/Asynchronous : Flag to set flow as Synchronous or Asynchronous (should the user be granted immediate
 access or wait for the Enzoic API to return.
* Credential Check Timeout : Timeout for password ping api and it should be enter in MilliSeconds
* User Attribute : The attribute on the users profile which which will contain output for Asynchronous flow results
. This attribute should be defined in AM identity store.
* Unique Identifier : The unique user identifying attribute to check against the Enzoic API.
* Local password file path : Local csv file location which contains compromised passwords.
* Local password Cache Expiration Time: The cache expiration for Local Password Check in seconds.
* Check Compromised Password : Boolean value to select whether to check password against local file or the Enzoic API.

![Screenshot from 2019-08-09 13-13-06](https://user-images.githubusercontent.com/20396535/62763279-c68e5700-baa8-11e9-9535-9566255cf185.png)
![Screenshot from 2019-08-27 14-21-45](https://user-images.githubusercontent.com/20396535/63756588-40f70d80-c8d6-11e9-9b35-e3d7dafb4b2c.png)



### Enzoic Reset Password

This node will collect new password to reset the password. 

Configuration is:
* Minimum Password Length : The minimum password length for new passwords.

![Screenshot from 2019-08-09 13-24-07](https://user-images.githubusercontent.com/20396535/62763373-01908a80-baa9-11e9-8d84-d69c76d90b36.png)



### Enzoic Save Password

This node will save new password for the user. There are no configurable attributes for it.

### Retry Limit Decision

Applies retry logic if entered password for reset password node is also a compromise password. This is a built in
 ForgeRock Node 

Configuration is:

* Retry Limit : The number of times to allow a retry.

![retry](https://user-images.githubusercontent.com/20396535/57918264-0849a000-78b4-11e9-905f-78ef61b88986.PNG)


### Message Node

Display message to the user. 

Configuration is:

* Message : Localisation overrides - as key fill shortcut for language (first will be used as default if not empty or
 "Default message" if empty), value is message for language defined by key.

* Positve Answer : Localisation overrides - as key fill shortcut for language (first will be used as default if not empty or "Yes" if empty), value is positive answer for language defined by key.

* Negative Answer : Localisation overrides - as key fill shortcut for language (first will be used as default if not
 empty or "No" if empty), value is negative answer for language defined by key.

![message](https://user-images.githubusercontent.com/20396535/57918307-1eeff700-78b4-11e9-870b-2eaa203e40ec.PNG)



## Configure the trees as follows


Enzoic Async Auth Tree :
Enzoic Async Auth Tree will check password is compromised or not using Enzoic Password ping API and proceeds with login without waiting for response from Enzoic. If password is compromised then user attribute is updated as True and if not, User attribute is updated as False. The customer can check this attribute for future AuthN or AuthZ and configure the flow according to the value of this user attribute.

 * Navigate to **Realm** > **Authentication** > **Trees** > **Create Tree**
 
 ![tree](https://user-images.githubusercontent.com/20396535/48189113-66c21e80-e365-11e8-8045-326786a41aca.PNG)
 
 
 ## Configuring Enzoic-Sync Auth Tree

The Enzoic Sync Auth Tree will check if the password is compromised using the Enzoic API. This tree then waits for
a response from Enzoic before proceeding. If the password is compromised, the user will not able to login.


Configuration of Enzoic-Sync Auth Tree depicted below:

![Enzoic_updatedTree](https://user-images.githubusercontent.com/20396535/57918407-5a8ac100-78b4-11e9-8e33-1f7bb0dd4e81.PNG)


 ## Configuring Enzoic-Async Auth Tree
 
The Enzoic Async Auth Tree will check password is compromised using Enzoic API and proceeds with
login without waiting for response. If the password is compromised then the user attribute is updated to True. If not,
 the user attribute is updated to False. The customer can check this attribute in future AuthN or AuthZ flows.

Configuration of Enzoic-Async Auth Tree depicted below:

![Screenshot from 2019-08-09 13-28-31](https://user-images.githubusercontent.com/20396535/62763610-9f845500-baa9-11e9-8f14-869d8b85384a.png)


