#-------------------------------------------------
#
# Project created by QtCreator 2015-01-28T16:11:01
#
#-------------------------------------------------

QT       += core network

QT       -= gui

TARGET = azril-dns
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    dnsserver.cpp \
    dnsservice.cpp \
    dnsclient.cpp \
    dnsservices.cpp

HEADERS += \
    dnspacket.h \
    dnsserver.h \
    dnsservice.h \
    dnsclient.h \
    dnsservices.h
