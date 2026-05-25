<?xml version="1.0" encoding="utf-8"?>
<!--
  heat transform: drop the auto-harvested component for quilrai.exe so it can be
  authored by hand in Product.wxs (where it carries the ServiceInstall /
  ServiceControl for the QuilrAIAgent service). Every other agent file stays
  in the harvested AgentFiles component group.

  Match is on the literal "\quilrai.exe". The proxy / monitor binaries contain
  "quilrai-" (with a hyphen), so contains() does NOT match them.
-->
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:wix="http://schemas.microsoft.com/wix/2006/wi"
    exclude-result-prefixes="wix">

  <xsl:output method="xml" indent="yes" omit-xml-declaration="no"/>

  <!-- Identity transform: copy everything by default. -->
  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>

  <!-- Key: components whose File Source ends in \quilrai.exe. -->
  <xsl:key name="quilraiExe"
           match="wix:Component[wix:File[contains(@Source, '\quilrai.exe')]]"
           use="@Id"/>

  <!-- Remove that component (in the DirectoryRef fragment)... -->
  <xsl:template match="wix:Component[key('quilraiExe', @Id)]"/>
  <!-- ...and its reference (in the ComponentGroup fragment). -->
  <xsl:template match="wix:ComponentRef[key('quilraiExe', @Id)]"/>

</xsl:stylesheet>
