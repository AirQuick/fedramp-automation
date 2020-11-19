<sch:schema xmlns:sch="http://purl.oclc.org/dsdl/schematron" queryBinding="xslt2"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:o="http://csrc.nist.gov/ns/oscal/1.0">

<sch:ns prefix="f"     uri="https://fedramp.gov/ns/oscal"/>
<sch:ns prefix="o"     uri="http://csrc.nist.gov/ns/oscal/1.0"/>
<sch:ns prefix="oscal" uri="http://csrc.nist.gov/ns/oscal/1.0"/>
<sch:ns prefix="lv"     uri="local-validations"/>

<sch:title>FedRAMP System Security Plan Validations</sch:title>

<!--
    Use XSL collection to load FedRAMP values, information types, and threats
    from a known source in a relative path instead of hard-coding filenames.
    All files are XML, but for future-proofing we filter to retrieve only XML
    files.
-->

<!-- 
    This workaround is only to allow XSpec to source the proper context for
    XPath at the global level. We use XSpec for unit testing, and this is a
    known issue with very well-documented work-arounds.
    
    https://gitter.im/usnistgov-OSCAL/FedRAMP-10x-Schematron?at=5fa06e38f2fd4f60fc4ccec7
    
    https://github.com/xspec/xspec/issues/873
    https://github.com/xspec/xspec/issues/892
    https://github.com/xspec/xspec/issues/1239

    See the updated documentation below about the global-context-item pattern.

    https://github.com/xspec/xspec/wiki/Writing-Scenarios/ec19017ab00d769b49786cb227e57eaa2e4ee2b2#global-context-item
    https://github.com/AirQuick/xspec/tree/14ccd455a0e420c97903c06f0faea86719031044/tutorial/global-context-item

    If not, you will definitely see this error like below when running the test suite.

    XPDY0002  Finding root of root/key-name the context item is absent
-->
<xsl:param as="document-node(element(o:system-security-plan))" name="global-context-item" select="." />
<xsl:param name="fedramp-registry-href" select="'../../xml?select=*.xml'" />
<xsl:variable name="fedramp-registry" select="collection($fedramp-registry-href)"/>

<!-- <sch:let name="sensitivity-levels" value="$fedramp-registry/f:fedramp-values/f:value-set[@name='security-sensitivity-level']/f:allowed-values/f:enum/@value"/>
<sch:let name="implementation-statuses" value="$fedramp-registry/f:fedramp-values/f:value-set[@name='control-implementation-status']/f:allowed-values/f:enum/@value"/> -->

<xsl:variable name="profile-map">
    <profile level="low" href="../../../baselines/xml/FedRAMP_LOW-baseline-resolved-profile_catalog.xml"/>
    <profile level="moderate" href="../../../baselines/xml/FedRAMP_MODERATE-baseline-resolved-profile_catalog.xml"/>
    <profile level="high" href="../../../baselines/xml/FedRAMP_HIGH-baseline-resolved-profile_catalog.xml"/>
</xsl:variable>

<xsl:key name="profile-lookup" match="profile" use="@level"/>
<xsl:variable name="selected-profile-href" select="key('profile-lookup', lv:sensitivity-level(), $profile-map)/@href"/>
<xsl:variable name="selected-profile" select="doc(resolve-uri($selected-profile-href))"/>

<xsl:function name="lv:if-empty-default">
    <xsl:param name="element"/>
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

<xsl:function name="lv:sensitivity-level">
    <xsl:variable name="path" select="$global-context-item/o:system-security-plan/o:system-characteristics/o:security-sensitivity-level"/>
    <xsl:sequence select="$path"/>
</xsl:function>

<xsl:function name="lv:validate-value">
    <xsl:param name="value-set" as="element()"/>
    <xsl:param name="value" as="xs:anyAtomicType"/>
    <xsl:variable name="values" select="$value-set/f:allowed-values/f:enum/@value"/>
    <xsl:message expand-text="yes">values: {$values}; value: {$value};</xsl:message>
    <xsl:choose>
        <!-- If allow-other is set, anything is valid. -->
        <xsl:when test="$value-set/f:allowed-values/@allow-other='no' and $value = $values"/>
        <xsl:otherwise>
            <xsl:value-of select="$values" separator=", "/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:function>

<!-- 
<xsl:function name="lv:format-allowed-values">
    <xsl:param name="values"/>
    <xsl:param name="separator" as="xs:string"/>
    <xsl:value-of select="$values" separator=", "/>
</xsl:function>
 -->

<!--     
<xsl:call-template name="lv:allowed-values-default">
        <xsl:with-param name="values" select="$values" />
    </xsl:call-template>
</xsl:function>
 -->
<!-- <xsl:template name="lv:allowed-values-default">
    <xsl:param name="values"><allowed-values/></xsl:param>
    <xsl:param name="separator" select="','"/>
    <xsl:variable name="result" select="string-join($values, $separator)"/>
    <xsl:message expand-text="yes">values: {$values} ; separator: {$separator} ; result: {$result}</xsl:message>
    <xsl:value-of select="$result"/>
</xsl:template> -->

<sch:pattern>
    <sch:rule context="/o:system-security-plan">
        <sch:assert role="fatal" id="no-fedramp-registry-values" test="exists($fedramp-registry/f:fedramp-values)">The FedRAMP Registry values are not present, this configuration is invalid.</sch:assert>
        <sch:assert role="fatal" id="no-security-sensitivity-level" test="boolean(lv:sensitivity-level())">No sensitivty level found.</sch:assert>
        <sch:let name="all" value="o:control-implementation/o:implemented-requirement[o:annotation[@name='implementation-status']]"/>
        <sch:let name="planned" value="o:control-implementation/o:implemented-requirement[o:annotation[@name='implementation-status' and @value='planned']]"/>
        <sch:let name="partial" value="o:control-implementation/o:implemented-requirement[o:annotation[@name='implementation-status' and @value='partial']]"/>
        <sch:assert id="invalid-implemented-requirements-count" test="count($all) > 0">There are no control implementations with statuses set.</sch:assert> 
        <sch:report id="partial-requirements-report" test="count($partial)">There are <sch:value-of select="count($partial)"/> partial<sch:value-of select="if (count($partial)=1) then ' control implementation' else ' control implementations'"/>.</sch:report>
        <sch:report id="planned-requirements-report" test="count($planned)">There are <sch:value-of select="count($planned)"/> planned<sch:value-of select="if (count($planned)=1) then ' control implementation' else ' control implementations'"/>.</sch:report>
        <sch:report id="all-requirements-report" test="count($all)">There are <sch:value-of select="count($all)"/> total<sch:value-of select="if (count($all)=1) then ' control implementation' else ' control implementations'"/>.</sch:report>
    </sch:rule>

    <sch:rule context="/o:system-security-plan/o:control-implementation">
        <sch:let name="required" value="$selected-profile/*//o:control"/>
        <sch:let name="implemented" value="o:implemented-requirement"/>
        <sch:let name="missing" value="$required[not(@id = $implemented/@control-id)]"/>
        <sch:report id="each-required-control-report" test="true()">The following <sch:value-of select="count($required)"/><sch:value-of select="if (count($required)=1) then ' control' else ' controls'"/> are required: <sch:value-of select="$required/@id"/></sch:report>
        <sch:assert id="incomplete-implementation-requirements" test="true()">This SSP has not implemented <sch:value-of select="count($missing)"/><sch:value-of select="if (count($missing)=1) then ' control' else ' controls'"/>: <sch:value-of select="$missing/@id"/></sch:assert>
    </sch:rule>

    <!-- <sch:rule context="/o:system-security-plan/o:control-implementation/o:implemented-requirement">
        <sch:let name="status" value="./o:annotation[@name='implementation-status']/@value"/>
        <sch:let name="corrections" value="lv:validate-value($fedramp-registry/f:fedramp-values/f:value-set[@name='control-implementation-status'], $status)"/>
        <sch:assert id="invalid-implementation-status" test="not(exists($corrections))">Invalid status '<sch:value-of select="$status"/>' for <sch:value-of select="./@control-id"/>, must be <sch:value-of select="$corrections"/></sch:assert>
    </sch:rule> -->

    <sch:rule context="/o:system-security-plan/o:system-characteristics/o:security-sensitivity-level">
        <sch:let name="corrections" value="lv:validate-value($fedramp-registry/f:fedramp-values/f:value-set[@name='security-sensitivity-level'], lv:if-empty-default(lv:sensitivity-level(), 'none'))"/>
        <sch:assert id="invalid-security-sensitivity-level" test="not(exists($corrections))"><sch:value-of select="./name()"/> is an invalid value '<sch:value-of select="lv:sensitivity-level()"/>', not an allowed value <sch:value-of select="$corrections"/>.
        </sch:assert>
    </sch:rule>
</sch:pattern>
</sch:schema>