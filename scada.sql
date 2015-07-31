SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL';

CREATE SCHEMA IF NOT EXISTS `scada` ;
USE `scada` ;

-- -----------------------------------------------------
-- Table `scada`.`NormalPackets`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `scada`.`NormalPackets` ;

CREATE  TABLE IF NOT EXISTS `scada`.`NormalPackets` (
  `idNormalPackets` INT NOT NULL AUTO_INCREMENT ,
  `frame_number` INT NULL ,
  `frame_time_relative` DOUBLE NULL ,
  `frame_time_delta_displayed` DOUBLE NULL ,
  `frame_len` INT NULL ,
  `ip_proto` VARCHAR(45) NULL ,
  `ip_version` VARCHAR(45) NULL ,
  `ip_src` VARCHAR(45) NULL ,
  `eth_src` VARCHAR(45) NULL ,
  `ip_dst` VARCHAR(45) NULL ,
  `eth_dst` VARCHAR(45) NULL ,
  `mbtcp_modbus_unit_id` VARCHAR(45) NULL ,
  `tcp_srcport` VARCHAR(45) NULL ,
  `tcp_dstport` VARCHAR(45) NULL ,
  `mbtcp_prot_id` VARCHAR(45) NULL ,
  `mbtcp_trans_id` INT NULL ,
  `mbtcp_len` INT NULL ,
  `mbtcp_modbus.func_code` VARCHAR(45) NULL ,
  `mbtcp_modbus.reference_num` VARCHAR(45) NULL ,
  `mbtcp_modbus.word_cnt` INT NULL ,
  `frameSecond` INT NULL ,
  `respFrameNumber` INT NULL ,
  `respTimeRel` DOUBLE NULL ,
  `respTimeDelta` DOUBLE NULL ,
  `respLen` INT NULL ,
  `respIpSrc` VARCHAR(45) NULL ,
  `respEthSrc` VARCHAR(45) NULL ,
  `respIpDest` VARCHAR(45) NULL ,
  `respEthDest` VARCHAR(45) NULL ,
  `respUnitId` VARCHAR(45) NULL ,
  `respSrcport` VARCHAR(45) NULL ,
  `respDstPort` VARCHAR(45) NULL ,
  `respProtId` VARCHAR(45) NULL ,
  `respTransId` VARCHAR(45) NULL ,
  `respMbtcpLen` INT NULL ,
  `respFuncCode` VARCHAR(45) NULL ,
  `respSecond` INT NULL ,
  `mbtcp.modbus.data` VARCHAR(45) NULL ,
  `d` INT NULL ,
  PRIMARY KEY (`idNormalPackets`) )
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8
COLLATE = utf8_unicode_ci
COMMENT = 'Packets sniffed from network during normal activity.';



SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
