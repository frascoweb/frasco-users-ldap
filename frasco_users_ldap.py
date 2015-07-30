from frasco import Feature, action, current_app, pass_feature, copy_extra_feature_options, ContextExitException
import ldap
from ldap.filter import escape_filter_chars


class UsersLdapFeature(Feature):
    name = "users_ldap"
    requires = ["users"]
    defaults = {"server": None,
                "use_tls": False,
                "bind_dn": None,
                "bind_password": None,
                "user_dn": '',
                "user_filter": "(&(objectClass=inetOrgPerson)(uid=%(user)s))",
                "username_attr": "uid",
                "email_attr": "mail",
                "additional_attrs": {},
                "group_flags": {},
                "group_dn": '',
                "group_filter": "(&(objectclass=groupOfNames)(cn=%(group)s))",
                "group_member_attr": "member",
                "track_uuid": False,
                "track_uuid_attr": "ldap_uuid"}

    def init_app(self, app):
        app.features.users.add_authentification_handler(self.authentify)
        if self.options['track_uuid']:
            app.features.models.ensure_model(app.features.users.model, **dict([
                (self.options['track_uuid_attr'], str)]))

    def connect(self, bind=True):
        conn = ldap.initialize(self.options['server'])
        ldap_opts = {}
        copy_extra_feature_options(self, ldap_opts)
        for key, value in ldap_opts:
            conn.set_option(getattr(ldap, 'OPT_%s' % key), value)
        if bind and self.options['bind_dn']:
            conn.simple_bind_s(self.options['bind_dn'].encode('utf-8'),
                self.options['bind_password'].encode('utf-8'))
        if self.options['use_tls']:
            conn.start_tls_s()
        return conn

    def search_user(self, id, conn=None):
        if not conn:
            conn = self.connect()
        filter = self.options['user_filter'] % {'user': escape_filter_chars(id)}
        rs = conn.search_s(self.options['user_dn'], ldap.SCOPE_SUBTREE, filter)
        if rs:
            return rs[0]

    def search_group(self, id, conn=None):
        if not conn:
            conn = self.connect()
        filter = self.options['group_filter'] % {'group': escape_filter_chars(id)}
        rs = conn.search_s(self.options['group_dn'], ldap.SCOPE_SUBTREE, filter)
        if rs:
            return rs[0]

    def is_member_of(self, group_dn, user_dn, member_attr=None, conn=None):
        if not conn:
            conn = self.connect()
        if not member_attr:
            member_attr = self.options['group_member_attr']
        return bool(conn.compare_s(group_dn, member_attr, user_dn))

    def authentify(self, username, password):
        try:
            conn = self.connect()
            dn, attrs = self.search_user(username, conn=conn)
            self.connect(bind=False).simple_bind_s(dn, password)
            return self._get_or_create_user_from_ldap(dn, attrs, conn=conn)
        except ldap.LDAPError, e:
            current_app.logger.error(e)

    @pass_feature('users')
    def _get_or_create_user_from_ldap(self, dn, attrs, users, conn=None):
        filters = {}
        if self.options['track_uuid']:
            filters[self.options['track_uuid_attr']] = attrs[self.options['track_uuid']][0]
        else:
            filters[users.options['email_column']] = attrs[self.options['email_attr']][0]
        user = users.query.filter(**filters).first()
        if user:
            return user

        user = users.model()
        user.email = attrs[self.options['email_attr']][0]
        user.username = attrs[self.options['username_attr']][0]
        if self.options['track_uuid']:
            setattr(user, self.options['track_uuid_attr'],
                attrs[self.options['track_uuid']][0])
        for target, src in self.options['additional_attrs'].iteritems():
            if src in attrs:
                setattr(user, target, attrs[src][0])

        memberships = {}
        for flag, group_dn in self.options['group_flags'].iteritems():
            if group_dn not in memberships:
                memberships[group_dn] = self.is_member_of(group_dn, dn, conn=conn)
            setattr(user, flag, memberships[group_dn])

        try:
            users.signup(user, must_provide_password=False, provider='ldap')
        except ContextExitException:
            return None
        return user