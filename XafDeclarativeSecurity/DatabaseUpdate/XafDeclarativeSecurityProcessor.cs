using System;
using System.Collections.Generic;
using System.Linq;
using DevExpress.Data.Filtering;
using DevExpress.ExpressApp;
using DevExpress.ExpressApp.DC;
using DevExpress.ExpressApp.Security;
using DevExpress.ExpressApp.Security.Strategy;
using DevExpress.Persistent.Base.Security;
using DevExpress.XtraPrinting.Native;

namespace XafDeclarativeSecurity.DatabaseUpdate
{
    internal class XafDeclarativeSecurityProcessor
    {
        public XafDeclarativeSecurityProcessor()
        {
            AdminRoleName = @"Administators";
            Users = new List<XafUserAttribute>();
            RoleParents = new List<XafRoleParentsAttribute>();
            TypePermissions = new List<XafTypePermisson>();
            ObjectPermissions = new List<XafObjectPermisson>();
            MemberPermissions = new List<XafMemberPermisson>();
        }

        internal class XafPermisson
        {
            public XafPermisson(Type targetType, IXafPermissions permissions)
            {
                TargetType = targetType;
                foreach (var propertyInfo in permissions.GetType().GetProperties())
                {
                    var myProp = GetType().GetProperties()
                        .FirstOrDefault(x => x.Name == propertyInfo.Name && x.CanWrite);

                    if (myProp != null)
                        myProp.SetValue(this, propertyInfo.GetValue(permissions, null), null);
                }
            }

            public Type TargetType { get; set; }
            public string RoleNames { get; set; }
            public string SecurityOperations { get; set; }
            public ObjectAccessModifier ObjectAccessModifier { get; set; }
        }
        internal class XafTypePermisson : XafPermisson
        {
            public XafTypePermisson(Type targetType, IXafTypePermissions permissions)
                : base(targetType, permissions)
            {
            }
        }
        internal class XafObjectPermisson : XafPermisson
        {
            public XafObjectPermisson(Type targetType, IXafObjectPermissions permissions)
                : base(targetType, permissions)
            {
            }
            public string Criteria { get; set; }
            public bool NotNavigable { get; set; }
        }
        internal class XafMemberPermisson : XafPermisson
        {
            public string MemberNames { get; set; }
            public string Criteria { get; set; }

            public XafMemberPermisson(Type targetType, string memberNames, IXafMemberPermissions permissions)
                : base(targetType, permissions)
            {
                MemberNames = memberNames;
            }
        }

        internal string AdminRoleName { get; set; }
        internal List<XafUserAttribute> Users { get; set; }
        internal List<XafRoleParentsAttribute> RoleParents { get; set; }
        internal List<XafTypePermisson> TypePermissions { get; set; }
        internal List<XafObjectPermisson> ObjectPermissions { get; set; }
        internal List<XafMemberPermisson> MemberPermissions { get; set; }

        public void Process(IObjectSpace objectSpace)
        {
            if (objectSpace != null)
            {
                gatherAttributes(objectSpace);
                doSimpleSecuritySystem(SecuritySystem.Instance as SecuritySimple, objectSpace);
                doNewSecuritySystem(SecuritySystem.Instance as SecurityStrategyComplex, objectSpace);
                objectSpace.CommitChanges();
            }
        }


        private void doNewSecuritySystem(SecurityStrategyComplex securityStrategyComplex, IObjectSpace objectSpace)
        {
            if (securityStrategyComplex != null)
            {
                // create admin role
                getRole(securityStrategyComplex, objectSpace, AdminRoleName);
                createPredefinedUsers(securityStrategyComplex, objectSpace);
                assignRoleParents(securityStrategyComplex, objectSpace);
                createTypePermissions(securityStrategyComplex, objectSpace);
                createObjectPermissions(securityStrategyComplex, objectSpace);
                createMemberPermissions(securityStrategyComplex, objectSpace);
            }
        }

        private void createMemberPermissions(SecurityStrategyComplex securityStrategyComplex, IObjectSpace objectSpace)
        {
            foreach (var memberPermisson in MemberPermissions)
            {
                foreach (var roleName in memberPermisson.RoleNames.Split(';'))
                {
                    var role = getRole(securityStrategyComplex, objectSpace, roleName);
                    role.EnsureTypePermissions(memberPermisson.TargetType, SecurityOperations.Navigate);
                    role.AddMemberAccessPermission(memberPermisson.TargetType, memberPermisson.MemberNames,
                        memberPermisson.SecurityOperations, memberPermisson.Criteria);
                }
            }
        }

        private void createObjectPermissions(SecurityStrategyComplex securityStrategyComplex, IObjectSpace objectSpace)
        {
            foreach (var objectPermisson in ObjectPermissions)
            {
                foreach (var roleName in objectPermisson.RoleNames.Split(';'))
                {
                    var role = getRole(securityStrategyComplex, objectSpace, roleName);
                    if(!objectPermisson.NotNavigable)
                        role.EnsureTypePermissions(objectPermisson.TargetType, SecurityOperations.Navigate);
                    role.AddObjectAccessPermission(objectPermisson.TargetType, objectPermisson.Criteria,
                        objectPermisson.SecurityOperations);
                }
            }
        }

        private void createTypePermissions(SecurityStrategyComplex securityStrategyComplex, IObjectSpace objectSpace)
        {
            foreach (var typePermisson in TypePermissions)
            {
                foreach (var roleName in typePermisson.RoleNames.Split(';'))
                {
                    var role = getRole(securityStrategyComplex, objectSpace, roleName);
                    role.EnsureTypePermissions(typePermisson.TargetType, typePermisson.SecurityOperations);
                }
            }
        }

        private void assignRoleParents(SecurityStrategyComplex securityStrategyComplex, IObjectSpace objectSpace)
        {
            foreach (var attribute in RoleParents)
            {
                var role = getRole(securityStrategyComplex, objectSpace, attribute.RoleName);
                foreach (var roleParentName in attribute.RoleParentsArray())
                {
                    var parent = getRole(securityStrategyComplex, objectSpace, roleParentName);
                    if (!role.ParentRoles.Contains(parent))
                        role.ParentRoles.Add(parent);
                }
            }
        }

        private void createPredefinedUsers(SecurityStrategyComplex securityStrategyComplex, IObjectSpace objectSpace)
        {
            foreach (var attribute in Users.Where(x => !string.IsNullOrEmpty(x.UserName)))
            {
                var userObj = objectSpace.FindObject(securityStrategyComplex.UserType,
                    new BinaryOperator("UserName", attribute.UserName));

                if (userObj == null)
                {
                    userObj = objectSpace.CreateObject(securityStrategyComplex.UserType);
                    var user = userObj as SecuritySystemUser;
                    if (user != null)
                    {
                        user.UserName = attribute.UserName;
                        attribute.RoleNamesArray()
                            .ForEach(x => user.Roles.Add(getRole(securityStrategyComplex, objectSpace, x)));
                    }
                }
            }
        }

        private SecuritySystemRole getRole(SecurityStrategyComplex securityStrategyComplex, 
            IObjectSpace objectSpace, string roleName)
        {
            SecuritySystemRole result = null;
            if (securityStrategyComplex != null && !string.IsNullOrEmpty(roleName))
            {
                result = objectSpace.FindObject(securityStrategyComplex.RoleType,
                    new BinaryOperator("Name", roleName)) as SecuritySystemRole;
                if (result == null)
                {
                    result = objectSpace.CreateObject(securityStrategyComplex.RoleType) as SecuritySystemRole;
                    if (result != null) result.Name = roleName;
                }
                result.IsAdministrative = roleName == AdminRoleName;
            }
            return result;
        }

        private void doSimpleSecuritySystem(SecuritySimple simpleSecurity, IObjectSpace objectSpace)
        {
            if (simpleSecurity != null)
            {
                foreach (var attribute in Users.Where(x => !string.IsNullOrEmpty(x.UserName)))
                {
                    var userObj = objectSpace.FindObject(simpleSecurity.UserType,
                        new BinaryOperator("UserName", attribute.UserName));
                    if (userObj == null)
                    {
                        userObj = objectSpace.CreateObject(simpleSecurity.UserType);
                        var simpleUser = userObj as ISimpleUser;
                        if (simpleUser != null)
                        {
                            var userNamePropInfo = simpleUser.GetType().GetProperties()
                                .FirstOrDefault(x => x.Name == "UserName");
                            if (userNamePropInfo != null && userNamePropInfo.CanWrite)
                                userNamePropInfo.SetValue(simpleUser, attribute.UserName, null);

                            simpleUser.IsActive = true;
                            simpleUser.IsAdministrator = attribute.RoleNamesArray().Contains(AdminRoleName);
                        }
                    }
                }
            }
        }

        private void gatherAttributes(IObjectSpace objectSpace)
        {
            var assemblies = (from ti in objectSpace.TypesInfo.PersistentTypes
                where ti.Type != null
                select ti.Type.Assembly).Distinct();

            var optionsType = (from a in assemblies
                from t in a.GetTypes()
                where t.GetCustomAttributes(typeof (XafAdminRoleNameAttribute), false).Cast<Attribute>().Any()
                select t).FirstOrDefault();

            gatherOptionsAttributes(optionsType);
            objectSpace.TypesInfo.PersistentTypes.ForEach(gatherTypeInfoAttributes);
        }

        private void gatherTypeInfoAttributes(ITypeInfo typeInfo)
        {
            var targetType = typeInfo.Type;

            scanAttributes<XafTypePermissonAttribute>(targetType, 
                x => TypePermissions.Add(new XafTypePermisson(targetType, x)));

            scanAttributes<XafObjectPermissionAttribute>(targetType,
                x => ObjectPermissions.Add(new XafObjectPermisson(targetType, x)));

            scanAttributes<XafMemberListPermissionAttribute>(targetType, 
                x => MemberPermissions.Add(new XafMemberPermisson(targetType, x.MemberNames, x)));

            foreach (var memberInfo in typeInfo.Members)
            {
                var memberName = memberInfo.Name;
                memberInfo.FindAttributes<XafMemberPermissionAttribute>()
                    .ForEach(x => MemberPermissions.Add(new XafMemberPermisson(targetType, memberName, x)));
            }
        }

        private void gatherOptionsAttributes(Type optionsType)
        {
            if (optionsType != null)
            {
                scanAttributes<XafAdminRoleNameAttribute>(optionsType, x => AdminRoleName = x.RoleName);
                scanAttributes<XafUserAttribute>(optionsType, x => Users.Add(x));
                scanAttributes<XafRoleParentsAttribute>(optionsType, x => RoleParents.Add(x));

                scanAttributes<XafExternalTypePermissionsAttribute>(optionsType,
                    x => TypePermissions.Add(new XafTypePermisson(x.TargetType, x)));

                scanAttributes<XafExternalObjectPermissionsAttribute>(optionsType,
                    x => ObjectPermissions.Add(new XafObjectPermisson(x.TargetType, x)));

                scanAttributes<XafExternalMemberPermissionsAttribute>(optionsType,
                    x => MemberPermissions.Add(new XafMemberPermisson(x.TargetType, x.MemberNames, x)));
            }
        }

        private void scanAttributes<TAttrbuteType>(Type sourceType, Action<TAttrbuteType> scanAction)
            where TAttrbuteType : Attribute
        {
            if (sourceType != null && scanAction != null)
                sourceType.GetCustomAttributes(typeof(TAttrbuteType), false).OfType<Attribute>()
                    .ForEach(x => scanAction((TAttrbuteType)x));
        }
    }
}