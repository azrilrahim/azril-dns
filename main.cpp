#include <QCoreApplication>
#include <dnsserver.h>
#include <dnsclient.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    dnsserver svr;
    DNSCLIENT cln;

    //cln.nslookup("gmail.com","10.193.3.10");
    cln.nslookup3("www.infoblox.com","10.193.3.10"
                                     "");
     //cln.nslookup("www.bnfoblox.com","8.8.8.8");
   // cln.nslookupTCP("www.infoblox.com","8.8.8.8");

    bool stat = svr.startServer();

    if (stat)
        qDebug() << "server start";
    else
        qDebug() << "Server down";

    return a.exec();
}
