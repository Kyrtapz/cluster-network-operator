package ovnkubeapprover

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	cnoclient "github.com/openshift/cluster-network-operator/pkg/client"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/csr"
	"github.com/openshift/library-go/pkg/operator/events"
	certapiv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

const (
	controllerName      = "ovnkube-node-csr-approver-controller"
	csrCommonNamePrefix = "openshift-ovn-kubernetes:ovnkube-controller:"
	nodeUserNamePrefix  = "system:node:" // nodeUserNamePrefix is the prefix for usernames in the form `system:node:<nodeName>`
)

type OVNKubeNodeApprover struct {
	csrCommonNamePrefix string
	groups              sets.Set[string]
}

func NewOVNKubeNodeApprover(commonNamePrefix string) *OVNKubeNodeApprover {
	return &OVNKubeNodeApprover{
		csrCommonNamePrefix: commonNamePrefix,
		groups:              sets.New[string]("system:nodes", "system:authenticated"),
	}
}

func (a *OVNKubeNodeApprover) Approve(csrObj *certapiv1.CertificateSigningRequest, x509CSR *x509.CertificateRequest) (approvalStatus csr.CSRApprovalDecision, denyReason string, err error) {
	if csrObj == nil || x509CSR == nil {
		return csr.CSRDenied, "Error", fmt.Errorf("received a 'nil' CSR")
	}

	if !strings.HasPrefix(csrObj.Spec.Username, nodeUserNamePrefix) {
		return csr.CSRDenied, fmt.Sprintf("CSR %q was created by an unexpected user: %q", csrObj.Name, csrObj.Spec.Username), nil
	}

	if csrGroups := sets.New[string](csrObj.Spec.Groups...); !csrGroups.Equal(a.groups) {
		return csr.CSRDenied, fmt.Sprintf("CSR %q was created by a user with unexpected groups: %v", csrObj.Name, csrGroups.UnsortedList()), nil
	}

	nodeName := strings.TrimPrefix(csrObj.Spec.Username, nodeUserNamePrefix)
	expectedSubject := fmt.Sprintf("%s%s", a.csrCommonNamePrefix, nodeName)
	if x509CSR.Subject.CommonName != expectedSubject {
		return csr.CSRDenied, fmt.Sprintf("expected the CSR's subject to be %q, but it is %q", expectedSubject, x509CSR.Subject.String()), nil
	}

	return csr.CSRApproved, "", nil

}

type requestCommonNameFilter struct {
	commonName string
}

func newRequestCommonNameFilter(commonName string) *requestCommonNameFilter {
	return &requestCommonNameFilter{commonName: commonName}
}

func (f *requestCommonNameFilter) Matches(csr *certapiv1.CertificateSigningRequest) bool {

	nsn := types.NamespacedName{Namespace: csr.Namespace, Name: csr.Name}
	csrPEM, _ := pem.Decode(csr.Spec.Request)
	if csrPEM == nil {
		klog.Errorf("Failed to PEM-parse the CSR block in .spec.request: no CSRs were found in %s", nsn)
		return false
	}

	x509CSR, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	if err != nil {
		klog.Infof("Failed to parse the CSR .spec.request of %q: %v", nsn, err)
		return false
	}

	return strings.HasPrefix(x509CSR.Subject.CommonName, f.commonName)
}

// TODO: The approver is not HA in CNO
// TODO: It should likely run in cluster-manager since it is OVN-K specific and could be used upstream,
// the problem is how to enable it during upgrade

func NewOVNKubeCSRApproverController(c cnoclient.Client, eventRecorder events.Recorder) (factory.Controller, error) {
	return csr.NewCSRApproverController(
		controllerName,
		nil,
		c.Default().Kubernetes().CertificatesV1().CertificateSigningRequests(),
		c.Default().InformerFactory().Certificates().V1().CertificateSigningRequests(),
		newRequestCommonNameFilter(csrCommonNamePrefix),
		NewOVNKubeNodeApprover(csrCommonNamePrefix),
		eventRecorder), nil
}
