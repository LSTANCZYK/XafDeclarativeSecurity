using DevExpress.ExpressApp.Security;

namespace XafDeclarativeSecurity
{
    public interface IXafPermissions
    {
        string RoleNames { get; set; }
        string SecurityOperations { get; set; }
        ObjectAccessModifier ObjectAccessModifier { get; set; }
    }

    public interface IXafTypePermissions : IXafPermissions
    {
    }

    public interface IXafCriteriaPermissions : IXafPermissions
    {
        string Criteria { get; set; }
    }

    public interface IXafObjectPermissions : IXafCriteriaPermissions
    {
        bool NotNavigable { get; set; }
    }

    public interface IXafMemberPermissions : IXafCriteriaPermissions
    {
    }
}
