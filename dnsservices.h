
#ifndef DNSSERVICES_H
#define DNSSERVICES_H

#include <QByteArray>
#include <dnspacket.h>
#include <QString>
#include <QtEndian>
#include <QHostAddress>

class DNSSERVICES
{
public:
    DNSSERVICES();
    ~DNSSERVICES();


    //==================
    QByteArray sWriteHeaderFlags(DNS_HEADER_FLAGS DH);
    DNS_HEADER_FLAGS sReadHeaderFlags(char *data, quint16 *offset);

    QByteArray sWriteQueryName(QString queryName);
    QString sReadQueryName( char *data, quint16 *offset);

    QByteArray sWriteQueryFlags(quint16 qType =1, quint16 qClass = 1);
    DNS_QUERY_FLAGS sReadQueryFlags( char *data, quint16 *offset);

    QByteArray sWriteAnswersFlags(DNS_ANSWER_FLAGS DAF);
    DNS_ANSWER_FLAGS sReadAnswerFlags (char *data, quint16 *offset);

    QByteArray sWriteRData ( void *data, quint16 size);
    QByteArray sWriteRData (quint32 data);

    QByteArray sReadRData (char *data, quint16 *offset, quint16 size);


private:
    QByteArray changeToDNSNameFormat(QString hostName);






};

#endif // DNSSERVICES_H
