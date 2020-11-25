<sch:schema xmlns:sch="http://purl.oclc.org/dsdl/schematron" queryBinding="xslt2"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:o="http://csrc.nist.gov/ns/oscal/1.0"
    xpath-default-namespace="http://csrc.nist.gov/ns/oscal/1.0">

<sch:ns prefix="f"     uri="https://fedramp.gov/ns/oscal"/>
<sch:ns prefix="o"     uri="http://csrc.nist.gov/ns/oscal/1.0"/>
<sch:ns prefix="oscal" uri="http://csrc.nist.gov/ns/oscal/1.0"/>
<sch:ns prefix="lv"     uri="local-validations"/>

<sch:title>FedRAMP System Security Plan Validations</sch:title>

<xsl:output method="xml" indent="yes" encoding="UTF-8"/>

<xsl:function name="lv:if-empty-default" as="item()">
    <xsl:param name="element" as="element()*"/>
    <xsl:param name="default" as="xs:anyAtomicType"/>
    <xsl:choose>
        <xsl:when test="not($element/*) and normalize-space($element)=''">
            <xsl:value-of select="$default"/>
        </xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="$element"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:function>

<xsl:function name="lv:registry" as="item()*">
    <xsl:param name="href"/>
    <xsl:sequence select="collection($href)"/>
</xsl:function>

<xsl:function name="lv:sensitivity-level" as="element()*">
    <xsl:param name="context" as="item()*"/>
    <xsl:sequence select="$context//o:security-sensitivity-level"/>
</xsl:function>

<xsl:function name="lv:profile" as="document-node()*">
    <xsl:param name="level" />
    <xsl:variable name="profile-map">
        <profile level="low" href="../../../baselines/xml/FedRAMP_LOW-baseline-resolved-profile_catalog.xml"/>
        <profile level="moderate" href="../../../baselines/xml/FedRAMP_MODERATE-baseline-resolved-profile_catalog.xml"/>
        <profile level="high" href="../../../baselines/xml/FedRAMP_HIGH-baseline-resolved-profile_catalog.xml"/>
    </xsl:variable>
    <xsl:variable name="href" select="$profile-map/profile[@level=$level]/@href"/>
    <xsl:sequence select="doc(resolve-uri($href))"/>
</xsl:function>

<xsl:function name="lv:correct">
    <xsl:param name="value-set" as="element()+"/>
    <xsl:param name="value"/>
    <xsl:variable name="values" select="$value-set/f:allowed-values/f:enum/@value"/>
    <xsl:choose>
        <!-- If allow-other is set, anything is valid. -->
        <xsl:when test="$value-set/f:allowed-values/@allow-other='no' and $value = $values"/>
        <xsl:otherwise>
            <xsl:value-of select="$values" separator=", "/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:function>

<!--
    For a given properties and attributes with OSCAL, there will be enumerable
    lists of items where do not wish to hard code the allowed-values/@enum 
    values in each Schematron rule. We will to abstract the assertions 
-->
<xsl:function name="lv:analyze">
    <xsl:param name="value-set" as="element()+"/>
    <xsl:param name="element" as="element()*"/>
    <xsl:variable name="results" as="node()*">
        <xsl:call-template name="analysis-template">
            <xsl:with-param name="value-set" select="$value-set"/>
            <xsl:with-param name="element" select="$element"/>
        </xsl:call-template>
    </xsl:variable>
    <xsl:sequence select="$results"/>
</xsl:function>

<xsl:function name="lv:report" as="xs:string">
    <xsl:param name="analysis" as="element()*"/>
    <xsl:variable name="results" as="xs:string">
        <xsl:call-template name="report-template">
            <xsl:with-param name="analysis" select="$analysis"/>
        </xsl:call-template>
    </xsl:variable>
    <xsl:value-of select="$results"/>
</xsl:function>

<xsl:template name="analysis-template" as="element()">
    <xsl:param name="value-set" as="element()*"/>
    <xsl:param name="element" as="element()*"/>
    <xsl:variable name="ok-values" select="$value-set/f:allowed-values/f:enum/@value"/>
    <analysis>
        <reports name="{$value-set/@name}"
            formal-name="{$value-set/f:formal-name}"
            description="{$value-set/f:description}"
            count="{count($element)}">
            <xsl:for-each select="$ok-values">
                <xsl:variable name="match" select="$element[@value=current()]"/>
                <report value="{current()}" count="{count($match)}"> 
                </report>
            </xsl:for-each>
        </reports>
    </analysis>
</xsl:template>

<xsl:template name="report-template" as="xs:string">
    <xsl:param name="analysis" as="element()*"/>
    <xsl:value-of>
        There are <xsl:value-of select="$analysis/reports/@count"/>&#xA0;<xsl:value-of select="$analysis/reports/@formal-name"/> items total, with
        <xsl:for-each select="$analysis/reports/report">
            <xsl:if test="position() gt 1 and not(position() eq last())">
                <xsl:value-of select="current()/@count"/> set as <xsl:value-of select="current()/@value"/>, </xsl:if>
            <xsl:if test="position() gt 1 and position() eq last()"
                > and <xsl:value-of select="current()/@count"/> set as <xsl:value-of select="current()/@value"/>.</xsl:if>
            <xsl:sequence select="."/>
        </xsl:for-each>
        There are <xsl:value-of select="($analysis/reports/@count - sum($analysis/reports/report/@count))"/> invalid items.
    </xsl:value-of>
</xsl:template>

<sch:pattern>
    <sch:rule context="/o:system-security-plan">
        <sch:let name="registry" value="'../../xml?select=*.xml' => lv:registry()"/>
        <sch:let name="selected-profile" value="/ => lv:sensitivity-level() => lv:profile()"/>
        <sch:let name="required-controls" value="$selected-profile/*//o:control"/>
        <sch:assert role="fatal" id="no-fedramp-registry-values" test="exists($registry/f:fedramp-values)">The FedRAMP Registry values are not present, this configuration is invalid.</sch:assert>
        <sch:assert role="fatal" id="no-security-sensitivity-level" test="empty(lv:sensitivity-level(/))">No sensitivty level found.</sch:assert>
        <sch:let name="results" value="lv:analyze($registry/f:fedramp-values/f:value-set[@name='control-implementation-status'], //o:implemented-requirement/o:annotation[@name='implementation-status'])"/>
        <sch:let name="total" value="$results/reports/@count"/>
        <sch:report id="stats-control-requirements" test="exists($results)"><sch:value-of select="$results => lv:report() => normalize-space()"/></sch:report>
    </sch:rule>

    <sch:rule context="/o:system-security-plan/o:control-implementation">
        <sch:let name="registry" value="'../../xml?select=*.xml' => lv:registry()"/>
        <sch:let name="selected-profile" value="/ => lv:sensitivity-level() => lv:profile()"/>
        <sch:let name="required-controls" value="$selected-profile/*//o:control"/>
        <sch:let name="implemented" value="o:implemented-requirement"/>
        <sch:let name="missing" value="$required-controls[not(@id = $implemented/@control-id)]"/>
        <sch:report id="each-required-control-report" test="exists(required-controls)">The following <sch:value-of select="count($required-controls)"/><sch:value-of select="if (count($required-controls)=1) then ' control' else ' controls'"/> are required: <sch:value-of select="$required-controls/@id"/></sch:report>
        <sch:assert id="incomplete-implementation-requirements" test="not(exists($missing))">This SSP has not implemented <sch:value-of select="count($missing)"/><sch:value-of select="if (count($missing)=1) then ' control' else ' controls'"/>: <sch:value-of select="$missing/@id"/></sch:assert>
    </sch:rule>

    <sch:rule context="/o:system-security-plan/o:control-implementation/o:implemented-requirement">
        <sch:let name="registry" value="'../../xml?select=*.xml' => lv:registry()"/>
        <sch:let name="status" value="./o:annotation[@name='implementation-status']/@value"/>
        <sch:let name="corrections" value="lv:correct($registry/f:fedramp-values/f:value-set[@name='control-implementation-status'], $status)"/>
        <sch:assert id="invalid-implementation-status" test="not(exists($corrections))">Invalid status '<sch:value-of select="$status"/>' for <sch:value-of select="./@control-id"/>, must be <sch:value-of select="$corrections"/></sch:assert>
    </sch:rule>

    <sch:rule context="//o:security-sensitivity-level">
        <sch:let name="registry" value="'../../xml?select=*.xml' => lv:registry()"/>
        <sch:let name="corrections" value="lv:correct($registry/f:fedramp-values/f:value-set[@name='security-sensitivity-level'], lv:if-empty-default(lv:sensitivity-level(/), 'none'))"/>
        <sch:assert id="invalid-security-sensitivity-level" test="not(exists($corrections))"><sch:value-of select="./name()"/> is an invalid value '<sch:value-of select="lv:sensitivity-level(/)"/>', not an allowed value <sch:value-of select="$corrections"/>.
        </sch:assert>
    </sch:rule>
</sch:pattern>
</sch:schema>