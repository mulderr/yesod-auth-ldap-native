{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE FlexibleContexts #-}

-----------------------------------------------------------------------------
-- |
-- Module      :  Yesod.Auth.LdapNative
-- Copyright   :  (C) 2015 Maciej Kazulak
-- License     :  BSD-style (see the file LICENSE)
--
-- Maintainer  :  Maciej Kazulak <kazulakm@gmail.com>
-- Stability   :  experimental
-- Portability :  portable
--
-- Yesod LDAP authentication plugin using Haskell native LDAP client.
----------------------------------------------------------------------------

module Yesod.Auth.LdapNative
  ( 
  -- * Usage
  -- $use

  -- * Plugin Configuration
    authLdap
  , authLdapWithForm
  
  -- * LDAP Configuration
  , LdapAuthConf
  , LdapAuthQuery (..)
  , mkLdapConf
  , mkGroupQuery
  , setHost
  , setPort
  , setUserQuery
  , setGroupQuery
  , setDebug

  -- * Re-exports
  , L.Host (..)
  ) where

import Yesod.Core
import Yesod.Auth
import Yesod.Form
import Control.Applicative ((<$>), (<*>))
import Control.Exception (SomeException, IOException, Handler (..), catches)
import Control.Monad.Trans.Class
import Control.Monad.Trans.Either
import Data.Text (Text)
import Data.List.NonEmpty (NonEmpty (..), (<|))
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Ldap.Client as L
import qualified Ldap.Client.Bind as L
import qualified Ldap.Client.Search as L
import Ldap.Client 
  (Ldap, Dn, Password (..), Filter (..), Mod, Search, Attr (..), AttrValue, Host, PortNumber, LdapError, SearchEntry (..))

pluginName :: Text
pluginName = "ldap"

loginRoute :: AuthRoute
loginRoute = PluginR pluginName ["login"]

-- | LDAP configuration.
-- 
-- Details hidden on purpose.
-- Use 'mkLdapConf' to create default config and functions below to adjust to taste.
data LdapAuthConf = LdapAuthConf
  -- connection
  { host   :: L.Host
  , port   :: L.PortNumber
  , bindDn :: L.Dn
  , bindPw :: L.Password
  
  -- queries
  , userQuery  :: LdapAuthQuery
  , groupQuery :: Maybe LdapAuthQuery

  -- other
  , debug  :: Int
  }

-- | Query parameters.
--
-- Standard LDAP query parameters except filter is a function of the username.
data LdapAuthQuery = LdapAuthQuery L.Dn (L.Mod L.Search) (Text -> L.Filter) [L.Attr]

-- | Default LDAP configuration.
mkLdapConf
  :: Text     -- ^ bindDn
  -> Text     -- ^ bindPw
  -> Text     -- ^ user query baseDn
  -> LdapAuthConf
mkLdapConf bindDn bindPw baseDn = LdapAuthConf
  { host   = L.Secure "localhost"
  , port   = 636
  , bindDn = L.Dn bindDn
  , bindPw = L.Password (T.encodeUtf8 bindPw)

  , userQuery  = mkUserQuery baseDn
  , groupQuery = Nothing

  , debug = 0
  }

-- | Default LDAP user query.
mkUserQuery
  :: Text       -- ^ baseDn
  -> LdapAuthQuery
mkUserQuery baseDn = LdapAuthQuery (L.Dn baseDn) (L.scope L.WholeSubtree)
  (\u -> L.And $
       L.Attr "objectClass" := "posixAccount"
    <| L.Attr "uid" L.:= T.encodeUtf8 u
    :| []
  ) []

-- | Default LDAP group query.
mkGroupQuery
  :: Text      -- ^ baseDn
  -> Text      -- ^ group name attr
  -> Text      -- ^ group name
  -> Text      -- ^ member attr
  -> LdapAuthQuery
mkGroupQuery baseDn groupAttr groupName memberAttr = LdapAuthQuery (L.Dn baseDn) (L.scope L.WholeSubtree)
  (\u -> L.And $
       L.Attr "objectClass" := "posixGroup"
    <| L.Attr groupAttr := T.encodeUtf8 groupName
    <| L.Attr memberAttr := T.encodeUtf8 u
    :| []
  ) []


setHost :: Host -> LdapAuthConf -> LdapAuthConf
setHost host conf = conf { host = host }

setPort :: PortNumber -> LdapAuthConf -> LdapAuthConf
setPort port conf = conf { port = port }

setUserQuery :: LdapAuthQuery -> LdapAuthConf -> LdapAuthConf
setUserQuery q conf = conf { userQuery = q }

setGroupQuery :: Maybe LdapAuthQuery -> LdapAuthConf -> LdapAuthConf
setGroupQuery q conf = conf { groupQuery = q }

setDebug :: Int -> LdapAuthConf -> LdapAuthConf
setDebug level conf = conf { debug = level }
  

authLdap :: YesodAuth m => LdapAuthConf -> AuthPlugin m
authLdap conf = authLdapWithForm conf defaultForm

authLdapWithForm :: (Yesod m, YesodAuth m) => LdapAuthConf -> (Route m -> WidgetT m IO ()) -> AuthPlugin m
authLdapWithForm conf form =
  AuthPlugin pluginName (dispatch conf) $ \tp -> form (tp loginRoute)


dispatch :: LdapAuthConf -> Text -> [Text] -> AuthHandler master TypedContent
dispatch conf "POST" ["login"] = dispatchLdap conf
dispatch _ _ _                 = notFound


-- | Returns the first value of each requested attr in credsExtra. Note this is only for
-- convenience in common use cases ie. create a user if not exists but will only work in
-- basic setups becase credsExtra is of type [(Text, Text)] - we loose type info and only
-- get the first value.
dispatchLdap :: (RenderMessage site FormMessage) => LdapAuthConf -> AuthHandler site TypedContent
dispatchLdap conf = do
  tp <- getRouteToParent
  (username, password) <- lift $ runInputPost $ (,)
    <$> ireq textField "username"
    <*> ireq textField "password"

  eb <- liftIO $
    -- not sure if we really should catch ALL exceptions here
    ldapLogin conf username password `catches` [Handler ioHandler, Handler catchAll]
  case eb of
    Left err -> do
      case debug conf > 0 of
        True  -> setMessage $ [shamlet|<div.alert.alert-danger>Sign in failure. Error: #{show err}|]
        False -> setMessage $ [shamlet|<div.alert.alert-danger>Sign in failure. That is all we know right now. Try again later.|]
      lift $ redirect $ tp LoginR
    Right (SearchEntry _ attrs) -> do
      let extra = map f attrs
      lift $ setCredsRedirect $ Creds pluginName username extra
  
  where
    f (L.Attr k, x : _) = (k, T.decodeUtf8 x)
    f (L.Attr k, _)     = (k, "")

    ioHandler :: IOException -> IO (Either LdapAuthError SearchEntry)
    ioHandler e = return $ Left $ IOException e

    catchAll :: SomeException -> IO (Either LdapAuthError SearchEntry)
    catchAll _ = return $ Left UnexpectedException


-- | LDAP authentication error.
data LdapAuthError =
    ResponseError L.ResponseError -- ^ Wraps "Ldap.Client" ResponseError.
  | LdapError L.LdapError         -- ^ Wraps "Ldap.Client" LdapError.
  | ServiceBindError              -- ^ Could not bind to directory using provided service credentials.
  | UserNotFoundError             -- ^ 'userQuery' returned nothing.
  | MultipleUsersError            -- ^ 'userQuery' returned multiple entries. You must either fix your query or your directory.
  | UserBindError                 -- ^ Could not bind as user. Probably wrong password.
  | GroupMembershipError          -- ^ 'groupQuery' was configured but returned nothing.

  | IOException IOException       -- ^ Probably connection error.
  | UnexpectedException           -- ^ Everything else.
  deriving (Eq, Show)


-- | LDAP authentication.
ldapLogin :: LdapAuthConf -> Text -> Text -> IO (Either LdapAuthError SearchEntry)
ldapLogin conf user pw = do
  res <- L.with (host conf) (port conf) $ \l ->
    
    runEitherT $ do
      -- service bind
      esb <- lift $ L.bindEither l (bindDn conf) (bindPw conf)
      case esb of
        Right _ -> return ()
        Left _ -> left ServiceBindError

      -- user search
      eu <- lift $ query l (userQuery conf) user
      se@(SearchEntry dn _) <- case eu of
        Right (x : []) -> return x
        Right [] -> left UserNotFoundError
        Right _  -> left MultipleUsersError
        Left err -> left $ ResponseError err

      -- verify group membership if groupQuery was given
      let mg = groupQuery conf
      eg <- case mg of
              Just g ->  lift $ query l g user
              Nothing -> return $ Right []
      case eg of
        -- either becase groupQuery was not provided or returned nothing
        Right [] -> case mg of 
                      Just _  -> left GroupMembershipError
                      Nothing -> return ()
        Right _  -> return ()
        Left err -> left $ ResponseError err

      -- user bind - verify password
      eub <- lift $ L.bindEither l dn (Password (T.encodeUtf8 pw))
      case eub of
        Right _ -> return ()
        Left _  -> left UserBindError

      return se

  case res of
    Left err -> return $ Left $ LdapError err
    Right x -> return x


-- | Search helper.
query :: Ldap -> LdapAuthQuery -> Text -> IO (Either L.ResponseError [SearchEntry])
query l (LdapAuthQuery baseDn mods filter attrs) login =
  L.searchEither l baseDn mods (filter login) attrs



defaultForm :: Yesod app => Route app -> WidgetT app IO ()
defaultForm loginR = [whamlet|
<form class="login-form" action="@{loginR}" method="post">
  <h2>Sign in
  <div.form-group>
    <label>Username
    <input.form-control type="text" name="username" required>
  <div.form-group>
    <label>Password
    <input.form-control type="password" name="password" required>
  <button.btn.btn-primary type="submit">Submit
|]


-- $use
--
-- This module follows the service bind approach. I will bite if you ask for prefix/suffix stuff.
--
-- Basic configuration in Foundation.hs:
--
-- > ldapConf :: LdapAuthConf
-- > ldapConf = 
-- >     setHost (Secure "127.0.0.1") $ setPort 636
-- >   $ mkLdapConf "cn=Manager,dc=example,dc=com" "v3ryS33kret" "ou=people,dc=example,dc=com"
--
-- And add __authLdap ldapConf__ to your __authPlugins__.
--
-- For plain connection (only for testing!):
--
-- > setHost (Plain "127.0.0.1")
--
-- For additional group authentication use 'setGroupQuery':
--
-- > ldapConf :: LdapAuthConf
-- > ldapConf = 
-- >     setGroupQuery (Just $ mkGroupQuery "ou=group,dc=example,dc=com" "cn" "it" "memberUid")
-- >   $ setHost (Secure "127.0.0.1") $ setPort 636
-- >   $ mkLdapConf "cn=yourapp,ou=services,dc=example,dc=com" "v3ryS33kret" "ou=people,dc=example,dc=com"
--
-- In the example above user jdoe will only be successfully authenticated when:
--
-- * service bind using the provided account is successful
-- * exactly one entry with objectclass=posixAccount and uid=jdoe exists somewhere in ou=people,dc=example,dc=com
-- * at least one group exists with cn=it and memberUid=jdoe in ou=group,dc=example,dc=com
--
-- Fine control of the queries is available with 'setUserQuery' and 'setGroupQuery'.
--
-- When testing or during initial configuration consider using 'setDebug' - set to 1 to enable. This will
-- give you exact error condition instead of "That is all we know". Never use it in production though as it
-- may reveal sensitive information.
-- 
-- Refer to 'ldap-client' documentation for details.
