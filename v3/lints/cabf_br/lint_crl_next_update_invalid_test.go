/*
 * ZLint Copyright 2026 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package cabf_br

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

/*
 * Explanation of test file names:
 *
 *      nup(1|0) = CRL nextUpdate is present (1) or absent (0)
 *      sub(1|0) = CRL covers (1) Subscriber certificates or not (0)
 *      len(1|0) = CRL lifespan is within (0) or beyond (1) the limit set by BRs
 *      eff(1|0) = CRL thisUpdate is before (0) this lint's effective date or after it (1)
 */

func TestCrlNextUpdateInvalid(t *testing.T) {

	type Data struct {
		input  string
		config string
		want   lint.LintStatus
	}
	data := []Data{
		{
			input: "crl_nextupdate_nup1_sub1_len0_eff0.pem",
			want:  lint.Pass,
		},
		{
			input: "crl_nextupdate_nup1_sub1_len1_eff0.pem",
			want:  lint.NE,
		},
		{
			input: "crl_nextupdate_nup1_sub1_len1_eff1.pem",
			want:  lint.Error,
		},
		{
			input: "crl_nextupdate_nup1_sub0_len0_eff0.pem",
			want:  lint.Pass,
			config: `
[e_crl_next_update_invalid]
SubscriberCRL = false`,
		},
		{
			input: "crl_nextupdate_nup1_sub0_len1_eff0.pem",
			want:  lint.NE,
			config: `
[e_crl_next_update_invalid]
SubscriberCRL = false`,
		},
		{
			input: "crl_nextupdate_nup1_sub0_len1_eff1.pem",
			want:  lint.Error,
			config: `
[e_crl_next_update_invalid]
SubscriberCRL = false`,
		},
		{
			input: "crl_nextupdate_nup0_sub0_len0_eff0.pem",
			want:  lint.NA,
		},
		// The following cases carry an Issuing Distribution Point that scopes
		// the CRL to CA or subscriber certificates. That in-band signal must
		// take precedence over the SubscriberCRL configuration default.
		{
			// IDP: onlyContainsCACerts; lifespan beyond 10 days but within
			// 12 months -> Pass without any configuration.
			input: "crl_nextupdate_idp_ca_eff1.pem",
			want:  lint.Pass,
		},
		{
			// IDP: onlyContainsCACerts; lifespan beyond 12 months -> still an
			// Error, proving the CA limit is really enforced.
			input: "crl_nextupdate_idp_ca_beyond12m_eff1.pem",
			want:  lint.Error,
		},
		{
			// IDP: onlyContainsUserCerts; lifespan beyond 10 days -> Error.
			input: "crl_nextupdate_idp_ee_eff1.pem",
			want:  lint.Error,
		},
		{
			// Config says CA, but the IDP says subscriber certs; the IDP wins.
			input: "crl_nextupdate_idp_ee_eff1.pem",
			config: `
[e_crl_next_update_invalid]
SubscriberCRL = false`,
			want: lint.Error,
		},
	}

	for _, testData := range data {
		testData := testData
		t.Run(testData.input, func(t *testing.T) {
			out := test.TestRevocationListLintWithConfig(t, "e_crl_next_update_invalid", testData.input, testData.config)
			if out.Status != testData.want {
				t.Errorf("expected %s, got %s", testData.want, out.Status)
			}
		})
	}
}
