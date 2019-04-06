

CREATE DATABASE  IF NOT EXISTS `socketdb` /*!40100 DEFAULT CHARACTER SET latin1 */;
USE `socketdb`;
-- MySQL dump 10.13  Distrib 5.7.17, for Win64 (x86_64)
--
-- Host: localhost    Database: socketdb
-- ------------------------------------------------------
-- Server version	5.7.25-0ubuntu0.18.04.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `DistinctDests`
--

DROP TABLE IF EXISTS `DistinctDests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `DistinctDests` (
  `DstIp` varchar(15) DEFAULT NULL,
  `DstIpHostname` varchar(45) DEFAULT NULL,
  `DstIpCity` varchar(45) DEFAULT NULL,
  `DstIpRegion` varchar(45) DEFAULT NULL,
  `DstIpCountry` varchar(45) DEFAULT NULL,
  `DstIpLoc` varchar(30) DEFAULT NULL,
  `DstIpOrg` varchar(30) DEFAULT NULL,
  `DstIpPostal` int(10) unsigned DEFAULT NULL,
  `DstPort` int(10) unsigned DEFAULT NULL,
  `Packets` bigint(20) unsigned DEFAULT NULL,
  `Bytes` bigint(20) unsigned DEFAULT NULL,
  `Proto` char(1) DEFAULT NULL,
  `SurveyRslts` varchar(45) DEFAULT NULL,
  `Remarks` varchar(45) DEFAULT NULL,
  `RepRmks` varchar(45) DEFAULT NULL,
  `Reputation` int(1) DEFAULT NULL,
  `DistctIntHosts` varchar(800) DEFAULT NULL,
  `uid` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `stamp_created` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `stamp_updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `ctxsent` int(9) DEFAULT NULL,
  `NetName` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`uid`),
  UNIQUE KEY `id_index5` (`DstIp`),
  KEY `id_index1` (`DstIp`),
  KEY `id_index2` (`DstIpHostname`),
  KEY `id_index3` (`Reputation`),
  KEY `id_index4` (`ctxsent`)
) ENGINE=InnoDB AUTO_INCREMENT=3639919 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ext_hosts`
--

DROP TABLE IF EXISTS `ext_hosts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ext_hosts` (
  `Ip` varchar(15) NOT NULL,
  `hostname` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`Ip`),
  UNIQUE KEY `Ip_UNIQUE` (`Ip`),
  UNIQUE KEY `hostname_UNIQUE` (`hostname`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `int_hosts`
--

DROP TABLE IF EXISTS `int_hosts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `int_hosts` (
  `ip` varchar(15) NOT NULL,
  `hostname` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`ip`),
  UNIQUE KEY `ip_UNIQUE` (`ip`),
  UNIQUE KEY `hostname_UNIQUE` (`hostname`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tabel1`
--

DROP TABLE IF EXISTS `tabel1`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tabel1` (
  `SrcIp` varchar(15) DEFAULT NULL,
  `SrcIpHostname` varchar(45) DEFAULT NULL,
  `SrcIpCity` varchar(45) DEFAULT NULL,
  `SrcIpRegion` varchar(20) DEFAULT NULL,
  `SrcIpCountry` varchar(20) DEFAULT NULL,
  `SrcIpLoc` varchar(30) DEFAULT NULL,
  `SrcIpOrg` varchar(45) DEFAULT NULL,
  `SrcIpPostal` int(10) unsigned DEFAULT NULL,
  `DstIp` varchar(15) DEFAULT NULL,
  `DstIpHostname` varchar(45) DEFAULT NULL,
  `DstIpCity` varchar(45) DEFAULT NULL,
  `DstIpRegion` varchar(45) DEFAULT NULL,
  `DstIpCountry` varchar(45) DEFAULT NULL,
  `DstIpLoc` varchar(30) DEFAULT NULL,
  `DstIpOrg` varchar(30) DEFAULT NULL,
  `DstIpPostal` int(10) unsigned DEFAULT NULL,
  `SrcPort` int(10) unsigned DEFAULT NULL,
  `DstPort` int(10) unsigned DEFAULT NULL,
  `Packets` int(10) unsigned DEFAULT NULL,
  `Bytes` bigint(20) unsigned DEFAULT NULL,
  `Proto` char(2) DEFAULT NULL,
  `SurveyRslts` varchar(45) DEFAULT NULL,
  `Remarks` varchar(46) DEFAULT NULL,
  `uid` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `stamp_created` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `stamp_updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `StartTime` varchar(16) DEFAULT NULL,
  `EndTime` varchar(16) DEFAULT NULL,
  `NetName` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`uid`),
  KEY `id_index` (`SrcIp`),
  KEY `id_index2` (`SrcIpHostname`),
  KEY `id_index3` (`DstIp`),
  KEY `id_index4` (`DstIpHostname`),
  KEY `idx_tabel1_DstPort` (`DstPort`),
  KEY `idx_tabel1_DstIpOrg` (`DstIpOrg`)
) ENGINE=InnoDB AUTO_INCREMENT=21224046 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `uid` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(45) DEFAULT NULL,
  `password` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`uid`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2019-01-27 17:46:52

