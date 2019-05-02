package random

import (
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/terraform/helper/schema"
	"golang.org/x/crypto/bcrypt"
)

/*********************************************************
  See resource_string.go for the implementation.
  resource_password and resource_string are intended to
  be identical other than the result of resource_password
  is treated as sensitive information.
*********************************************************/

func resourcePassword() *schema.Resource {
	resourcePassword := resourceString()
	resourcePassword.Create = CreatePassword
	resourcePassword.Update = UpdatePassword
	resourcePassword.Schema["result"].Sensitive = true
	resourcePassword.Schema["bcrypt_cost"] = &schema.Schema{
		Type:     schema.TypeInt,
		Optional: true,
		Default:  12,
		ForceNew: false,
	}
	resourcePassword.Schema["bcrypt"] = &schema.Schema{
		Type:     schema.TypeString,
		Computed: true,
	}
	return resourcePassword
}

func CreatePassword(d *schema.ResourceData, meta interface{}) (err error) {
	if err = CreateString(d, meta); err != nil {
		return err
	}
	d.SetId("none")
	RepopulateHash(d, meta)
	return nil
}

func UpdatePassword(d *schema.ResourceData, meta interface{}) (err error) {
	RepopulateHash(d, meta)
	return nil
}

func RepopulateHash(d *schema.ResourceData, _ interface{}) error {
	bcryptCost := d.Get("bcrypt_cost").(int)
	result := d.Get("result").(string)

	hash, err := bcrypt.GenerateFromPassword([]byte(result), bcryptCost)
	if err != nil {
		return errwrap.Wrapf("error generating bcrypt value: {{err}}", err)
	}
	d.Set("bcrypt", string(hash))

	return nil
}
