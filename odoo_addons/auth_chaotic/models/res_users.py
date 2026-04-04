from odoo import models, fields

class ResUsers(models.Model):
    _inherit = 'res.users'

    chaotic_enabled = fields.Boolean(string="Chaotic Hardware Auth Enabled", default=False)
    chaotic_device_ids = fields.Char(string="Authorized Hardware Device IDs")
