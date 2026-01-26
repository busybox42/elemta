<?php

/*
 +-----------------------------------------------------------------------+
 | Enhanced Roundcube Configuration for Elemta MTA
 | Utilizes comprehensive LDAP schema with email features
 +-----------------------------------------------------------------------+
 */

// Database configuration
$config['db_dsnw'] = 'sqlite:////var/roundcube/db/sqlite.db?mode=0646';

// IMAP Configuration - Connect to Dovecot
$config['default_host'] = 'elemta-dovecot';
$config['default_port'] = 14143;
$config['imap_timeout'] = 120;
$config['imap_auth_type'] = 'PLAIN';
$config['imap_delimiter'] = null;
$config['imap_ns_personal'] = null;
$config['imap_ns_other'] = null;
$config['imap_ns_shared'] = null;
$config['imap_force_caps'] = false;
$config['imap_force_lsub'] = false;
$config['imap_force_ns'] = false;
$config['imap_conn_options'] = null;

// SMTP Configuration - Connect to Elemta MTA
$config['smtp_server'] = 'elemta';
$config['smtp_port'] = 2525;
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$config['smtp_auth_type'] = 'PLAIN';
$config['smtp_timeout'] = 120;
$config['smtp_conn_options'] = null;

// Interface Configuration
$config['support_url'] = '';
$config['product_name'] = 'Elemta Webmail Enhanced';
$config['des_key'] = 'elemta_webmail_secure_key_2025_enhanced';
$config['plugins'] = array(
    'archive',
    'zipdownload',
    'markasjunk',
    'managesieve',
    'password',
    'identity_select',
    'newmail_notifier',
    'emoticons',
    'show_additional_headers'
);

// Security Settings
$config['session_lifetime'] = 30; // 30 minutes
$config['ip_check'] = true;
$config['referer_check'] = true;
$config['x_frame_options'] = 'deny';

// User Interface - Use LDAP preferences
$config['skin'] = 'elastic';
$config['language'] = 'en_US';
$config['timezone'] = 'UTC';
$config['date_format'] = 'Y-m-d';
$config['time_format'] = 'H:i';

// Message Composition
$config['draft_autosave'] = 60;
$config['max_message_size'] = '25M';
$config['mdn_requests'] = 0;

// Enhanced Address Book Configuration (LDAP Integration with Filters)
$config['ldap_public'] = array(
    // All Company Directory
    'elemta_directory' => array(
        'name'          => 'All Company Users',
        'hosts'         => array('elemta-ldap'),
        'port'          => 389,
        'use_tls'       => false,
        'ldap_version'  => '3',
        'network_timeout' => 10,
        'user_specific' => false,
        'base_dn'       => 'ou=people,dc=example,dc=com',
        'bind_dn'       => 'cn=admin,dc=example,dc=com',
        'bind_pass'     => 'admin',
        'search_fields' => array('mail', 'cn', 'uid', 'sn', 'givenName', 'title', 'departmentNumber'),
        'fieldmap' => array(
            'name'        => 'cn',
            'surname'     => 'sn',
            'firstname'   => 'givenName',
            'email'       => 'mail',
            'phone:work'  => 'telephoneNumber',
            'department'  => 'departmentNumber',
            'jobtitle'    => 'title',
            'notes'       => 'description',
        ),
        'sort'          => 'cn',
        'scope'         => 'sub',
        'filter'        => '(&(objectClass=inetOrgPerson)(mail=*)(!(employeeType=test)))',
        'fuzzy_search'  => true,
        'vlv'           => false,
        'sizelimit'     => 0,
        'timelimit'     => 0,
        'referrals'     => false,
        'writable'      => false,
        'global_search' => true,
        'groups' => array(
            'base_dn'     => 'ou=groups,dc=example,dc=com',
            'filter'      => '(objectClass=groupOfNames)',
            'object_classes' => array('top', 'groupOfNames'),
            'member_attr' => 'member',
            'name_attr'   => 'cn',
            'email_attr'  => 'mail',
        ),
    ),
    
    // Management Team
    'management' => array(
        'name'          => 'Management Team',
        'hosts'         => array('elemta-ldap'),
        'port'          => 389,
        'use_tls'       => false,
        'ldap_version'  => '3',
        'network_timeout' => 10,
        'user_specific' => false,
        'base_dn'       => 'ou=people,dc=example,dc=com',
        'bind_dn'       => 'cn=admin,dc=example,dc=com',
        'bind_pass'     => 'admin',
        'search_fields' => array('mail', 'cn', 'title'),
        'fieldmap' => array(
            'name'        => 'cn',
            'surname'     => 'sn',
            'firstname'   => 'givenName',
            'email'       => 'mail',
            'phone:work'  => 'telephoneNumber',
            'jobtitle'    => 'title',
            'department'  => 'departmentNumber',
        ),
        'sort'          => 'cn',
        'scope'         => 'sub',
        'filter'        => '(&(objectClass=inetOrgPerson)(employeeType=management))',
        'fuzzy_search'  => true,
        'writable'      => false,
        'global_search' => true,
    ),
    
    // Engineering Team
    'engineering' => array(
        'name'          => 'Engineering Team',
        'hosts'         => array('elemta-ldap'),
        'port'          => 389,
        'use_tls'       => false,
        'ldap_version'  => '3',
        'network_timeout' => 10,
        'user_specific' => false,
        'base_dn'       => 'ou=people,dc=example,dc=com',
        'bind_dn'       => 'cn=admin,dc=example,dc=com',
        'bind_pass'     => 'admin',
        'search_fields' => array('mail', 'cn', 'title', 'employeeType'),
        'fieldmap' => array(
            'name'        => 'cn',
            'surname'     => 'sn',
            'firstname'   => 'givenName',
            'email'       => 'mail',
            'phone:work'  => 'telephoneNumber',
            'jobtitle'    => 'title',
        ),
        'sort'          => 'cn',
        'scope'         => 'sub',
        'filter'        => '(&(objectClass=inetOrgPerson)(departmentNumber=engineering))',
        'fuzzy_search'  => true,
        'writable'      => false,
        'global_search' => true,
    ),
    
    // By Department
    'sales_marketing' => array(
        'name'          => 'Sales & Marketing',
        'hosts'         => array('elemta-ldap'),
        'port'          => 389,
        'use_tls'       => false,
        'ldap_version'  => '3',
        'network_timeout' => 10,
        'user_specific' => false,
        'base_dn'       => 'ou=people,dc=example,dc=com',
        'bind_dn'       => 'cn=admin,dc=example,dc=com',
        'bind_pass'     => 'admin',
        'search_fields' => array('mail', 'cn', 'title'),
        'fieldmap' => array(
            'name'        => 'cn',
            'email'       => 'mail',
            'phone:work'  => 'telephoneNumber',
            'jobtitle'    => 'title',
            'department'  => 'departmentNumber',
        ),
        'sort'          => 'departmentNumber',
        'scope'         => 'sub',
        'filter'        => '(&(objectClass=inetOrgPerson)(|(departmentNumber=sales)(departmentNumber=marketing)))',
        'fuzzy_search'  => true,
        'writable'      => false,
        'global_search' => true,
    ),
    
    // Support & HR
    'support_hr' => array(
        'name'          => 'Support & HR',
        'hosts'         => array('elemta-ldap'),
        'port'          => 389,
        'use_tls'       => false,
        'ldap_version'  => '3',
        'network_timeout' => 10,
        'user_specific' => false,
        'base_dn'       => 'ou=people,dc=example,dc=com',
        'bind_dn'       => 'cn=admin,dc=example,dc=com',
        'bind_pass'     => 'admin',
        'search_fields' => array('mail', 'cn', 'title'),
        'fieldmap' => array(
            'name'        => 'cn',
            'email'       => 'mail',
            'phone:work'  => 'telephoneNumber',
            'jobtitle'    => 'title',
            'department'  => 'departmentNumber',
        ),
        'sort'          => 'cn',
        'scope'         => 'sub',
        'filter'        => '(&(objectClass=inetOrgPerson)(|(departmentNumber=support)(departmentNumber=hr)))',
        'fuzzy_search'  => true,
        'writable'      => false,
        'global_search' => true,
    ),
);

// User preferences from LDAP
$config['user_preferences'] = array(
    'language'    => 'mailPreferredLanguage',
    'skin'        => 'mailUITheme',
    'signature'   => 'mailSignature',
);

// Logging
$config['log_driver'] = 'stdout';
$config['log_level'] = 4;
$config['per_user_logging'] = false;

// Disable installer
$config['enable_installer'] = false;

// Additional security
$config['force_https'] = false; // Set to true in production
$config['login_autocomplete'] = 2;
$config['password_charset'] = 'UTF-8';

// Performance
$config['enable_caching'] = true;
$config['messages_cache'] = 'db';
$config['imap_cache'] = 'db';

// Managesieve (Sieve filters) - Enhanced with LDAP
$config['managesieve_port'] = 4190;
$config['managesieve_host'] = 'elemta-dovecot';
$config['managesieve_auth_type'] = null;
$config['managesieve_auth_cid'] = null;
$config['managesieve_auth_pw'] = null;
$config['managesieve_usetls'] = false;

// Enhanced Password plugin configuration for LDAP
$config['password_driver'] = 'ldap';
$config['password_ldap_host'] = 'elemta-ldap';
$config['password_ldap_port'] = 389;
$config['password_ldap_starttls'] = false;
$config['password_ldap_version'] = 3;
$config['password_ldap_basedn'] = 'ou=people,dc=example,dc=com';
$config['password_ldap_method'] = 'user';
$config['password_ldap_adminDN'] = 'cn=admin,dc=example,dc=com';
$config['password_ldap_adminPW'] = 'admin';
$config['password_ldap_search_base'] = 'ou=people,dc=example,dc=com';
$config['password_ldap_search_filter'] = '(&(objectClass=inetOrgPerson)(mail=%login))';
$config['password_ldap_passwdattr'] = 'userPassword';
$config['password_ldap_force_replace'] = true;
$config['password_ldap_lchattr'] = '';
$config['password_ldap_samba'] = false;

// Identity management - Multiple email addresses from LDAP
$config['identity_select_plugin'] = array(
    'additional_sources' => array(
        'ldap' => array(
            'fields' => array(
                'email' => 'mailAlternateAddress',
                'name'  => 'cn',
                'signature' => 'mailSignature',
            ),
        ),
    ),
);

// Auto-reply functionality
$config['vacation_driver'] = 'ldap';
$config['vacation_ldap'] = array(
    'hosts'         => array('elemta-ldap'),
    'port'          => 389,
    'bind_dn'       => 'cn=admin,dc=example,dc=com',
    'bind_pass'     => 'admin',
    'base_dn'       => 'ou=people,dc=example,dc=com',
    'search_filter' => '(&(objectClass=mailUser)(mail=%login))',
    'enabled_attr'  => 'mailAutoReplyEnabled',
    'message_attr'  => 'mailAutoReply',
);

// Enhanced quota display
$config['quota_driver'] = 'ldap';
$config['quota_ldap'] = array(
    'hosts'         => array('elemta-ldap'),
    'port'          => 389,
    'bind_dn'       => 'cn=admin,dc=example,dc=com',
    'bind_pass'     => 'admin',
    'base_dn'       => 'ou=people,dc=example,dc=com',
    'search_filter' => '(&(objectClass=mailUser)(mail=%login))',
    'quota_attr'    => 'mailQuota',
);

// Mail forwarding display (read-only in webmail)
$config['forwarding_info'] = array(
    'ldap' => array(
        'hosts'         => array('elemta-ldap'),
        'port'          => 389,
        'bind_dn'       => 'cn=admin,dc=example,dc=com',
        'bind_pass'     => 'admin',
        'base_dn'       => 'ou=people,dc=example,dc=com',
        'search_filter' => '(&(objectClass=mailUser)(mail=%login))',
        'forward_attr'  => 'mailForwardingAddress',
    ),
);

// Additional headers to show forwarding info
$config['show_additional_headers'] = array(
    'X-Forwarded-To',
    'X-Auto-Reply-Enabled',
    'X-Mail-Quota',
);

// Enhanced compose settings
$config['compose_save_localstorage'] = true;
$config['compose_responses_static'] = false;

// Spell checking
$config['spellcheck_engine'] = 'aspell';
$config['spellcheck_languages'] = array(
    'da' => 'Dansk',
    'de' => 'Deutsch',
    'en' => 'English',
    'es' => 'Español',
    'fr' => 'Français',
    'it' => 'Italiano',
    'nl' => 'Nederlands',
    'pt' => 'Português',
    'sv' => 'Svenska',
);

?> 