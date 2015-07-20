import frappe
import json
from frappe.utils.response import build_response

# allow_guest=True
@frappe.whitelist()
def get_companynames():
	fields = json.loads(frappe.local.form_dict['fields'])
	data = frappe.model.db_query.DatabaseQuery("Company").execute(fields=fields, ignore_permissions=True)

	frappe.local.response.update({
			"data":  data
		})
