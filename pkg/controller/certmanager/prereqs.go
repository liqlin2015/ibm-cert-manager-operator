//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package certmanager

import (
	"context"
	"strings"

	operatorv1alpha1 "github.com/ibm/ibm-cert-manager-operator/pkg/apis/operator/v1alpha1"
	res "github.com/ibm/ibm-cert-manager-operator/pkg/resources"
	"github.com/pkg/errors"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionclientsetv1beta1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Check all RBAC is ready for cert-manager
func checkRbac(instance *operatorv1alpha1.CertManager, scheme *runtime.Scheme, client client.Client, ns string) error {
	if rolesError := roles(instance, scheme, client, ns); rolesError != nil {
		return rolesError
	}
	return nil
}

func roles(instance *operatorv1alpha1.CertManager, scheme *runtime.Scheme, client client.Client, ns string) error {

	if serviceAccountErr := createServiceAccount(instance, scheme, client, ns); serviceAccountErr != nil {
		return serviceAccountErr
	}
	if roleErr := createRole(instance, scheme, client, ns); roleErr != nil {
		return roleErr
	}
	if len(ns) == 0 {
		if err := escalateRoleToClusterPermission(client, ns); err != nil {
			return err
		}

	}
	if clusterRoleErr := createClusterRole(instance, scheme, client, ns); clusterRoleErr != nil {
		return clusterRoleErr
	}

	return nil
}

func escalateRoleToClusterPermission(client client.Client, ns string) error {
	log.Info("Escalating role to cluster permission")
	clusterRole := &rbacv1.ClusterRole{}
	err := client.Get(context.Background(), types.NamespacedName{Name: res.RoleName, Namespace: ""}, clusterRole)
	if err != nil && apiErrors.IsNotFound(err) {

		clusterRole = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: res.RoleName,
			},
			Rules: res.DefaultRole.Rules,
		}
		err := client.Create(context.Background(), clusterRole)
		if err != nil {
			return err
		}
	}

	// Creating clusterrolebinding
	log.Info("Escalating rolebinding to cluster permission")
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: res.RoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				APIGroup:  "",
				Name:      res.ServiceAccount,
				Namespace: ns,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     res.RoleName,
		},
	}
	err = client.Create(context.Background(), binding)
	if err != nil && !apiErrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func createRole(instance *operatorv1alpha1.CertManager, scheme *runtime.Scheme, client client.Client, ns string) error {
	log.Info("Creating role")
	role := &rbacv1.Role{}
	err := client.Get(context.Background(), types.NamespacedName{Name: res.RoleName, Namespace: ns}, role)
	if err != nil && apiErrors.IsNotFound(err) {
		// res.DefaultClusterRole.ResourceVersion = ""

		r := res.DefaultRole.DeepCopy()
		r.ObjectMeta.Namespace = ns
		// if err := controllerutil.SetControllerReference(instance, r, scheme); err != nil {
		// 	log.Error(err, "Error setting controller reference on role")
		// }
		err := client.Create(context.Background(), r)
		if err != nil {
			return err
		}
	}

	log.Info("Creating rolebinding")
	// Creating Rolebinding
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      res.RoleName,
			Namespace: ns,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "ServiceAccount",
				APIGroup: "",
				Name:     res.ServiceAccount,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     res.RoleName,
		},
	}
	err = client.Create(context.Background(), binding)
	if err != nil && !apiErrors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func createClusterRole(instance *operatorv1alpha1.CertManager, scheme *runtime.Scheme, client client.Client, ns string) error {
	log.Info("Creating cluster role")
	clusterRole := &rbacv1.ClusterRole{}
	err := client.Get(context.Background(), types.NamespacedName{Name: res.ClusterRoleName, Namespace: ""}, clusterRole)
	if err != nil && apiErrors.IsNotFound(err) {
		// res.DefaultClusterRole.ResourceVersion = ""

		// if err := controllerutil.SetControllerReference(instance, res.DefaultClusterRole, scheme); err != nil {
		// 	log.Error(err, "Error setting controller reference on clusterrole")
		// }
		err := client.Create(context.Background(), res.DefaultClusterRole)
		if err != nil {
			return err
		}
	}

	// Creating clusterrolebinding
	log.Info("Creating clusterrolebinding")
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: res.ClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				APIGroup:  "",
				Name:      res.ServiceAccount,
				Namespace: ns,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     res.ClusterRoleName,
		},
	}
	err = client.Create(context.Background(), binding)
	if err != nil && !apiErrors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

// func createClusterRoleBinding(instance *operatorv1alpha1.CertManager, scheme *runtime.Scheme, client client.Client, namespace string) error {
// 	log.V(2).Info("Creating cluster role binding")
// 	clusterRoleBinding := &rbacv1.ClusterRoleBinding{}

// 	err := client.Get(context.Background(), types.NamespacedName{Name: res.ClusterRoleName, Namespace: ""}, clusterRoleBinding)
// 	if err != nil && apiErrors.IsNotFound(err) {
// 		// res.DefaultClusterRoleBinding.ResourceVersion = ""
// 		res.DefaultClusterRoleBinding.Subjects[0].Namespace = namespace

// 		// if err := controllerutil.SetControllerReference(instance, res.DefaultClusterRoleBinding, scheme); err != nil {
// 		// 	log.Error(err, "Error setting controller reference on clusterrolebinding")
// 		// }
// 		err := client.Create(context.Background(), res.DefaultClusterRoleBinding)
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }

func createServiceAccount(instance *operatorv1alpha1.CertManager, scheme *runtime.Scheme, client client.Client, namespace string) error {
	log.Info("Creating service account")
	res.DefaultServiceAccount.ResourceVersion = ""
	res.DefaultServiceAccount.Namespace = namespace

	if err := controllerutil.SetControllerReference(instance, res.DefaultServiceAccount, scheme); err != nil {
		log.Error(err, "Error setting controller reference on service account")
	}

	err := client.Create(context.Background(), res.DefaultServiceAccount)
	if err != nil {
		if !apiErrors.IsAlreadyExists(err) {
			log.V(2).Info("Error creating the service account, but was not an already exists error", "error message", err)
			return err
		}
	}
	return nil
}

// Checks to ensure the namespace we're deploying the service in exists
// func checkNamespace(instance *operatorv1alpha1.CertManager, scheme *runtime.Scheme, client typedCorev1.NamespaceInterface) error {
// 	getOpt := metav1.GetOptions{}

// 	if _, err := client.Get(res.DeployNamespace, getOpt); err != nil && apiErrors.IsNotFound(err) {
// 		if err = controllerutil.SetControllerReference(instance, res.NamespaceDef, scheme); err != nil {
// 			log.Error(err, "Error setting controller reference on namespace")
// 		}
// 		log.V(1).Info("cert-manager namespace does not exist, creating it", "error", err)
// 		if _, err = client.Create(res.NamespaceDef); err != nil {
// 			return err
// 		}
// 	} else if err != nil {
// 		return err
// 	}
// 	log.V(2).Info("cert-manager namespace exists")
// 	return nil
// }

// Checks for the existence of all certmanager CRDs
// Takes action to create them if they do not exist
func checkCrds(instance *operatorv1alpha1.CertManager, scheme *runtime.Scheme, client apiextensionclientsetv1beta1.CustomResourceDefinitionInterface, name, namespace string) error {
	var allErrors []string
	listOptions := metav1.ListOptions{}
	customResourcesList, err := client.List(listOptions)
	if err != nil {
		return err
	}

	existingResources := make(map[string]bool)
	for _, item := range customResourcesList.Items {
		if strings.Contains(item.Name, res.GroupVersion) {
			existingResources[item.Name] = false
		}
	}

	// Check that the CRDs we need match the ones we got from the cluster
	for _, item := range res.CRDs {
		crName := item + "." + res.GroupVersion
		if _, ok := existingResources[crName]; !ok { // CRD wasn't found, create it
			log.V(1).Info("Did not find custom resource, creating it now", "resource", item)
			crd := res.CRDMap[item]

			// if err := controllerutil.SetControllerReference(instance, crd, scheme); err != nil {
			// 	log.Error(err, "Error setting controller reference on crd")
			// }
			if _, err = client.Create(crd); err != nil {
				allErrors = append(allErrors, err.Error())
			}
		}
	}
	if allErrors != nil {
		return errors.New(strings.Join(allErrors, "\n"))
	}
	log.V(2).Info("Finished checking CRDs, no errors found")
	return nil
}

// Removes the clusterrole and clusterrolebinding created by this operator
func removeRoles(client client.Client) error {
	// Delete the clusterrolebinding
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{}

	err := client.Get(context.Background(), types.NamespacedName{Name: res.ClusterRoleName, Namespace: ""}, clusterRoleBinding)
	if err != nil && apiErrors.IsNotFound(err) {
		log.V(1).Info("Error getting cluster role binding", "msg", err)
		return nil
	} else if err == nil {
		if err = client.Delete(context.Background(), clusterRoleBinding); err != nil {
			log.V(1).Info("Error deleting cluster role binding", "name", clusterRoleBinding.Name, "error message", err)
			return err
		}
	} else {
		return err
	}
	// Delete the clusterrole
	clusterRole := &rbacv1.ClusterRole{}
	err = client.Get(context.Background(), types.NamespacedName{Name: res.ClusterRoleName, Namespace: ""}, clusterRole)
	if err != nil && apiErrors.IsNotFound(err) {
		log.V(1).Info("Error getting cluster role", "msg", err)
		return nil
	} else if err == nil {
		if err = client.Delete(context.Background(), clusterRole); err != nil {
			log.V(1).Info("Error deleting cluster role", "name", clusterRole.Name, "error message", err)
			return err
		}
	} else {
		return err
	}
	return nil
}

//CheckRhacm checks if RHACM exists
func checkRhacm(client client.Client) error {

	multiClusterHubType := &unstructured.Unstructured{}
	multiClusterHubType.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "operator.open-cluster-management.io",
		Kind:    "MultiClusterHub",
		Version: "v1",
	})

	rhacmErr := client.Get(context.Background(), types.NamespacedName{
		Namespace: "open-cluster-management",
		Name:      "multiclusterhub",
	}, multiClusterHubType)

	return rhacmErr

}
