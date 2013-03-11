# cas-slo-cluster
===============

CAS ServletFilter to replicate a Single LogOut (SLO) request in a clustered environment.

## How it works

The ServletFilter need to be configured with the list of URL each node of the cluster can be access.
And with the hostname of the current node (to avoid sendind a request to himself).

When a CAS SLO (sent in POST) is catch by the SLO Cluster Filter, the request is "forward" 
to all other configured nodes in the cluster.

The "forward" requests are sent asynchronously in POST to the same path the original one, 
but using the host URL provided in peers configuration field.

## Packaging

The ServletFilter should be packaged as an external jar and embeded in the classpath 
of the webapp (usually /WEB-INF/lib).

## Web.xml configuration example

    <filter>
      <filter-name>CAS SLO Cluster Filter</filter-name>
      <filter-class>org.esco.cas.client.CasSingleLogoutClusterFilter</filter-class>
      <init-param>
        <param-name>clientHostName</param-name>
        <param-value>alouette.foo.net</param-value>
      </init-param>
      <init-param>
        <param-name>peersUrls</param-name>
        <param-value>https://rossignol.foo.net:8443,https://alouette.foo.net:8443</param-value>
      </init-param>
    </filter>
    
    <filter-mapping>
      <filter-name>CAS SLO Cluster Filter</filter-name>
      <url-pattern>/*</url-pattern>
    </filter-mapping>
    
    <filter>
      <filter-name>CAS Single Sign Out Filter</filter-name>
      <filter-class>org.jasig.cas.client.session.SingleSignOutFilter</filter-class>
    </filter>
    
    <filter-mapping>
      <filter-name>CAS Single Sign Out Filter</filter-name>
      <url-pattern>/*</url-pattern>
    </filter-mapping>
    
    <listener>
    <listen er-class>org.jasig.cas.client.session.SingleSignOutHttpSessionListener</listener-class>
    </listener>
    
    <filter>
      <filter-name>CAS Validation Filter</filter-name>
      [ ... ]
    </filter-mapping>
