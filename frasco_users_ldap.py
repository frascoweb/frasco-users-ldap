from frasco import Feature, action, current_app, pass_feature, copy_extra_feature_options, ContextExitException, signal
import ldap
from ldap.filter import escape_filter_chars


class UsersLdapFeature(Feature):
    name = "users_ldap"
    requires = ["users"]
    defaults = {"server": None,
                "use_tls": False,
                "tls_cacert_dir": None,
                "tls_cacert_file": None,
                "tls_cert_file": None,
                "tls_key_file": None,
                "tls_require_cert": None,
                "tls_demand": False,
                "bind_dn": None,
                "bind_password": None,
                "user_dn": '',
                "user_filter": "(&(objectClass=inetOrgPerson)(uid=%(user)s))",
                "username_attr": "uid",
                "append_username_domain": None,
                "strip_username_domain": True,
                "email_attr": "mail",
                "additional_attrs": {},
                "group_flags": {},
                "group_dn": '',
                "group_filter": "(&(objectclass=groupOfNames)(cn=%(group)s))",
                "group_member_attr": "member",
                "group_member_uid_user_attr": None,
                "track_uuid": False,
                "track_uuid_attr": "ldap_uuid"}

    ldap_login = signal('users_ldap_login')
    ldap_signup = signal('users_ldap_signup')

    def init_app(self, app):
        app.features.users.add_authentification_handler(self.authentify)
        if self.options['track_uuid']:
            app.features.models.ensure_model(app.features.users.model, **dict([
                (self.options['track_uuid_attr'], str)]))

    def connect(self, bind=True):
        if self.options['tls_require_cert']:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        elif self.options['tls_require_cert'] is False:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        if self.options['tls_cacert_dir']:
            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, self.options['tls_cacert_dir'])
        if self.options['tls_cacert_file']:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self.options['tls_cacert_file'])
        if self.options['tls_cert_file']:
            ldap.set_option(ldap.OPT_X_TLS_CERTFILE, self.options['tls_cert_file'])
        if self.options['tls_key_file']:
            ldap.set_option(ldap.OPT_X_TLS_KEYFILE, self.options['tls_key_file'])

        conn = ldap.initialize(self.options['server'])

        if self.options['tls_demand']:
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            conn.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
            conn.set_option(ldap.OPT_X_TLS_DEMAND, True)

        ldap_opts = {}
        copy_extra_feature_options(self, ldap_opts)
        for key, value in ldap_opts.iteritems():
            conn.set_option(getattr(ldap, 'OPT_%s' % key.upper()), value)

        if bind and self.options['bind_dn']:
            conn.simple_bind_s(self.options['bind_dn'].encode('utf-8'),
                self.options['bind_password'].encode('utf-8'))

        if self.options['use_tls']:
            conn.start_tls_s()

        return conn

    def search_objects(self, base_dn, filter, conn=None):
        if not conn:
            conn = self.connect()
        return conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter)

    def search_user(self, id, conn=None):
        filter = self.options['user_filter'] % {'user': escape_filter_chars(id)}
        rs = self.search_objects(self.options['user_dn'], filter, conn)
        if rs:
            return rs[0]

    def search_group(self, id, conn=None):
        filter = self.options['group_filter'] % {'group': escape_filter_chars(id)}
        rs = self.search_objects(self.options['group_dn'], filter, conn)
        if rs:
            return rs[0]

    def is_member_of(self, group_dn, user_dn, member_attr=None, conn=None, ignore_errors=True):
        if not conn:
            conn = self.connect()
        if not member_attr:
            member_attr = self.options['group_member_attr']
        try:
            return bool(conn.compare_s(group_dn, member_attr, user_dn))
        except ldap.LDAPError as e:
            if not ignore_errors:
                raise
            return False

    def authentify(self, username, password):
        try:
            conn = self.connect()
            if self.options['append_username_domain'] and "@" not in username:
                username += "@" + self.options['append_username_domain']
            ldap_user = self.search_user(username, conn=conn)
            if ldap_user:
                dn, attrs = ldap_user
                self.connect(bind=False).simple_bind_s(dn, password)
                return self._get_or_create_user_from_ldap(dn, attrs, conn=conn)
        except ldap.LDAPError as e:
            current_app.log_exception(e)

    @pass_feature('users')
    def _get_or_create_user_from_ldap(self, dn, attrs, users, conn=None):
        filters = {}
        if self.options['track_uuid']:
            filters[self.options['track_uuid_attr']] = attrs[self.options['track_uuid']][0]
        else:
            filters[users.options['email_column']] = attrs[self.options['email_attr']][0].lower()
        user = users.query.filter(**filters).first()
        if user:
            self.ldap_login.send(self, user=user, dn=dn, attrs=attrs, conn=conn)
            return user

        username = attrs[self.options['username_attr']][0]
        if "@" in username and self.options['strip_username_domain']:
            username = username.split('@')[0]

        user = users.model()
        user.email = attrs[self.options['email_attr']][0]
        user.username = username
        if self.options['track_uuid']:
            setattr(user, self.options['track_uuid_attr'],
                attrs[self.options['track_uuid']][0])
        for target, src in self.options['additional_attrs'].iteritems():
            if src in attrs:
                setattr(user, target, attrs[src][0])

        memberships = {}
        for flag, group_dn in self.options['group_flags'].iteritems():
            member = getattr(user, self.options['group_member_uid_user_attr'])\
                        if self.options['group_member_uid_user_attr'] else dn
            if group_dn not in memberships:
                memberships[group_dn] = self.is_member_of(group_dn, member, conn=conn)
            setattr(user, flag, memberships[group_dn])

        try:
            users.signup(user, must_provide_password=False, provider='ldap')
        except ContextExitException:
            return None

        self.ldap_signup.send(self, user=user, dn=dn, attrs=attrs, conn=conn)
        return user
