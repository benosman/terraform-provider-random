package random

import (
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
)

/*********************************************************
  See resource_string_test.go for the additional details.
  resource_password and resource_string are intended to
  be identical other than the result of resource_password
  is treated as sensitive information.
*********************************************************/

func TestAccResourcePassword(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: strings.Replace(testAccResourceStringConfig, "random_string", "random_password", -1),
				Check: resource.ComposeTestCheckFunc(
					testAccResourceStringCheck("random_password.foo", &customLens{
						customLen: 12,
					}),
					testAccResourceStringCheck("random_password.bar", &customLens{
						customLen: 32,
					}),
					testAccResourceStringCheck("random_password.three", &customLens{
						customLen: 4,
					}),
					patternMatch("random_password.three", "!!!!"),
					testAccResourceStringCheck("random_password.min", &customLens{
						customLen: 12,
					}),
					regexMatch("random_password.min", regexp.MustCompile(`([a-z])`), 2),
					regexMatch("random_password.min", regexp.MustCompile(`([A-Z])`), 3),
					regexMatch("random_password.min", regexp.MustCompile(`([0-9])`), 4),
					regexMatch("random_password.min", regexp.MustCompile(`([!#@])`), 1),
				),
			},
		},
	})
}
