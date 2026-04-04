{
    'name': 'Chaotic Hardware Authentication',
    'version': '1.0',
    'category': 'Security',
    'summary': 'zkSNARK and Hardware Attested Authentication bridge',
    'description': """
        Integrates the Chaotic Authentication system (zkSNARK + TPM) with Odoo.
        Requires a running Chaotic FastAPI backend.
    """,
    'author': 'Antigravity',
    'depends': ['base', 'web'],
    'data': [
        'views/chaotic_login_templates.xml',
    ],
    'assets': {
        'web.assets_frontend': [
            'auth_chaotic/static/src/js/chaotic_login.js',
        ],
    },
    'installable': True,
    'application': False,
    'license': 'LGPL-3',
}
