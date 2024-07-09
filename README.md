Welcome to the WSO2 Identity Server (IS) Wordpress authenticator. 

WSO2 IS is one of the best Identity Servers, which enables you to offload your identity and user entitlement management burden totally from your application. It comes with many features, supports many industry standards and most importantly it allows you to extent it according to your security requirements. This repo contains Authenticators written to work with different third party systems. 

With WSO2 IS, there are lot of provisioning capabilities available. There are 3 major concepts as Inbound, outbound provisioning and Just-In-Time provisioning. Inbound provisioning means , provisioning users and groups from an external system to IS. Outbound provisioning means , provisioning users from IS to other external systems. JIT provisioning means , once a user tries to login from an external IDP, a user can be created on the fly in IS with JIT. Repos under this account holds such components invlove in communicating with external systems.

Pre-requisites:
- Maven 3.x
- Java 1.6 or above

Tested Platform: 
- UBUNTU 14.04
- Java 1.7

Do the following:
1. Navigate to wordpress-authenticator/org.wso2.carbon.identity.authenticator.wordpress and build.
2. Place org.wso2.carbon.identity.authenticator jar into <IS_HOME>/repository/components/dropins.
3. Start the IS server and create Identity provider and service provider in IS via the IS console.
