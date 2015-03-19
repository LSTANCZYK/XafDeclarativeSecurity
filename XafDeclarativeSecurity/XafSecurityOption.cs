using System;
using DevExpress.ExpressApp.Security;

namespace XafDeclarativeSecurity
{
    public abstract class XafSecurityOption : Attribute
    {
    }

    /// <summary>
    /// Application administrative role name
    /// </summary>
    [AttributeUsage(AttributeTargets.Class)]
    public class XafAdminRoleNameAttribute : XafSecurityOption
    {
        /// <summary>
        /// Administrative role name
        /// </summary>
        public string RoleName { get; set; }

        public XafAdminRoleNameAttribute(string roleName)
        {
            RoleName = roleName;
        }
    }

    /// <summary>
    /// Predefined application user
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
    public class XafUserAttribute : XafSecurityOption
    {
        /// <summary>
        /// Application user name
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// Application user roles (semicolumn separated)
        /// </summary>
        public string RoleNames { get; set; }

        /// <summary>
        /// Convert role names to array
        /// </summary>
        /// <returns></returns>
        public string[] RoleNamesArray()
        {
            var result = RoleNames == null ? new string[] {} : RoleNames.Split(';');
            return result;
        }

        public XafUserAttribute(string userName, string roleNames)
        {
            UserName = userName;
            RoleNames = roleNames;
        }
    }

    /// <summary>
    /// Role parents
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
    public class XafRoleParentsAttribute : XafSecurityOption
    {
        /// <summary>
        /// Role name
        /// </summary>
        public string RoleName { get; set; }

        /// <summary>
        /// Role parents names (separated by semicolumn)
        /// </summary>
        public string RoleParents { get; set; }

        public string[] RoleParentsArray()
        {
            var result = RoleParents == null ? new string[] { } : RoleParents.Split(';');
            return result;
        }

        public XafRoleParentsAttribute(string roleName,  string roleParents)
        {
            RoleName = roleName;
            RoleParents = roleParents;
        }
    }

    public abstract class XafExternalPermissionsAttribute : XafSecurityOption
    {
        /// <summary>
        /// Type, permissions applying to 
        /// </summary>
        public Type TargetType { get; set; }

        /// <summary>
        /// Operations to permit or decline (see SecurityOperations static class members)
        /// </summary>
        public string SecurityOperations { get; set; }

        /// <summary>
        /// Object access modifier (allow or decline permissions)
        /// </summary>
        public ObjectAccessModifier ObjectAccessModifier { get; set; }

        /// <summary>
        /// Application user roles (semicolumn separated)
        /// </summary>
        public string RoleNames { get; set; }

        public XafExternalPermissionsAttribute(Type targetType, string roleNames, string securityOperations)
        {
            TargetType = targetType;
            RoleNames = roleNames;
            SecurityOperations = securityOperations;
        }
    }

    /// <summary>
    /// Type permissions for external class
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
    public class XafExternalTypePermissionsAttribute : XafExternalPermissionsAttribute, IXafTypePermissions
    {
        public XafExternalTypePermissionsAttribute(Type targetType, string roleNames, string securityOperations) 
            : base(targetType, roleNames, securityOperations)
        {
        }
    }
    
    /// <summary>
    /// Criteria aware attribute
    /// </summary>
    public abstract class XafExternalCriteriaPermissionsAttribute : XafExternalPermissionsAttribute
    {
        protected XafExternalCriteriaPermissionsAttribute(Type targetType, string roleNames, string securityOperations, string criteria = "")
            : base(targetType, roleNames, securityOperations)
        {
            Criteria = criteria;
        }

        /// <summary>
        /// XPO selection criteria expression
        /// </summary>
        public string Criteria { get; set; }
    }

    /// <summary>
    /// Permissions to objects selected with Criteria
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
    public class XafExternalObjectPermissionsAttribute : XafExternalCriteriaPermissionsAttribute, IXafObjectPermissions
    {
        public XafExternalObjectPermissionsAttribute(Type targetType, string roleNames, string securityOperations, string criteria = "") 
            : base(targetType, roleNames, securityOperations, criteria)
        {
        }

        public bool NotNavigable { get; set; }
    }

    /// <summary>
    /// Members permissions
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
    public class XafExternalMemberPermissionsAttribute : XafExternalCriteriaPermissionsAttribute, IXafMemberPermissions
    {
        /// <summary>
        /// Member names
        /// </summary>
        public string MemberNames { get; set; }

        public XafExternalMemberPermissionsAttribute(Type targetType, string roleNames, string memberNames, 
            string securityOperations, string criteria = "") 
            : base(targetType, roleNames, securityOperations, criteria)
        {
            MemberNames = memberNames;
        }
    }
}
