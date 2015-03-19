using System;
using DevExpress.ExpressApp.Security;

namespace XafDeclarativeSecurity
{
    /// <summary>
    /// Base xaf permission attribute class
    /// </summary>
    public abstract class XafPermissionAttribute : Attribute
    {
        /// <summary>
        /// Role names separated by semicolumn
        /// </summary>
        public string RoleNames { get; set; }
        /// <summary>
        /// Security operations to declare (see SecurityOperations static class)
        /// </summary>
        public string SecurityOperations { get; set; }
        /// <summary>
        /// Object access modifier (allow or decline permissions)
        /// </summary>
        public ObjectAccessModifier ObjectAccessModifier { get; set; }

        public string[] RoleNamesArray()
        {
            var result = RoleNames == null ? new string[] {} : RoleNames.Split(';');
            return result;
        }

        public XafPermissionAttribute(string roleNames, string securityOperations)
        {
            ObjectAccessModifier = ObjectAccessModifier.Allow;
            RoleNames = roleNames;
            SecurityOperations = securityOperations;
        }
    }

    /// <summary>
    /// Type (class or interface) permissions for specified roles
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Interface, AllowMultiple = true)]
    public class XafTypePermissonAttribute : XafPermissionAttribute, IXafTypePermissions
    {
        public XafTypePermissonAttribute(string roleNames, string securityOperations) 
            : base(roleNames, securityOperations)
        {
        }
    }

    /// <summary>
    /// Criteria aware attribute
    /// </summary>
    public abstract class XafCriteriaPermissionsAttribute : XafPermissionAttribute
    {
        protected XafCriteriaPermissionsAttribute(string roleNames, string securityOperations, string criteria = "") 
            : base(roleNames, securityOperations)
        {
            Criteria = criteria;
        }

        /// <summary>
        /// Selection criteria expression
        /// </summary>
        public string Criteria { get; set; }
    }

    /// <summary>
    /// Roles permissions for specified objects
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Interface, AllowMultiple = true)]
    public class XafObjectPermissionAttribute : XafCriteriaPermissionsAttribute, IXafObjectPermissions
    {
        public XafObjectPermissionAttribute(string roleNames, string securityOperations, string criteria = "") 
            : base(roleNames, securityOperations, criteria)
        {
        }

        public bool NotNavigable { get; set; }
    }

    /// <summary>
    /// Roles permissions for member, attribute applied to
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = true)]
    public class XafMemberPermissionAttribute : XafCriteriaPermissionsAttribute, IXafMemberPermissions
    {
        public XafMemberPermissionAttribute(string roleNames, string securityOperations, string criteria = "") 
            : base(roleNames, securityOperations, criteria)
        {
        }
    }

    /// <summary>
    /// Roles permissions for members
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Interface, AllowMultiple = true)]
    public class XafMemberListPermissionAttribute : XafCriteriaPermissionsAttribute, IXafMemberPermissions
    {
        /// <summary>
        /// Member names separated by semicolumn
        /// </summary>
        public string MemberNames { get; set; }

        public XafMemberListPermissionAttribute(string roleNames, string memberNames, string securityOperations, string criteria = "") 
            : base(roleNames, securityOperations, criteria)
        {
            MemberNames = memberNames;
        }
    }
}
