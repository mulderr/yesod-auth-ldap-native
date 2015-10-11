# yesod-auth-ldap-native
Yesod LDAP authentication plugin using native Haskell Ldap.Client

* does not depend on system libraries
* service account bind
* customizable

## Usage

This module follows the service bind approach. I will bite if you ask for prefix/suffix stuff.

Basic configuration in `Foundation.hs`:
```haskell
ldapConf :: LdapAuthConf
ldapConf = 
    setHost (Secure "127.0.0.1") $ setPort 636
  $ mkLdapConf "cn=Manager,dc=example,dc=com" "v3ryS33kret"
      "ou=people,dc=example,dc=com"
```

 And add __authLdap ldapConf__ to your __authPlugins__.

 For plain connection (only for testing!):
```haskell
setHost (Plain "127.0.0.1")
```

 For additional group authentication use 'setGroupQuery':
```haskell
 ldapConf :: LdapAuthConf
 ldapConf = 
     setGroupQuery (Just $ mkGroupQuery
       "ou=group,dc=example,dc=com" "cn" "it" "memberUid")
   $ setHost (Secure "127.0.0.1") $ setPort 636
   $ mkLdapConf "cn=yourapp,ou=services,dc=example,dc=com"
       "v3ryS33kret"
       "ou=people,dc=example,dc=com"
```

In the example above user jdoe will only be successfully authenticated when:

* service bind using the provided account is successful
* exactly one entry with objectclass=posixAccount and uid=jdoe exists somewhere in ou=people,dc=example,dc=com
* at least one group exists with cn=it and memberUid=jdoe in ou=group,dc=example,dc=com

Fine control of the queries is available with `setUserQuery` and `setGroupQuery`.

When testing or during initial configuration consider using `setDebug` - set to 1 to enable. This will
give you exact error condition instead of "That is all we know". Never use it in production though as it
may reveal sensitive information.
 
Refer to `ldap-client` documentation for details.
