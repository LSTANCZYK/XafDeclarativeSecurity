using System;
using DevExpress.ExpressApp;
using DevExpress.ExpressApp.Updating;

namespace XafDeclarativeSecurity.DatabaseUpdate
{
    public class Updater : ModuleUpdater
    {
        public Updater(IObjectSpace objectSpace, Version currentDBVersion) :
            base(objectSpace, currentDBVersion)
        {
        }

        public override void UpdateDatabaseAfterUpdateSchema()
        {
            base.UpdateDatabaseAfterUpdateSchema();
            (new XafDeclarativeSecurityProcessor()).Process(ObjectSpace);
        }
    }
}
