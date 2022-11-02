package com.test.sonar;



import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONArray;
import org.json.JSONObject;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import javax.net.ssl.SSLException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

@Component
@EnableScheduling
@EnableAsync
public class NepalCrawler {
    @Autowired
    private MongoDocumentObject mObject;

    @Autowired
    private WebClientConfig clientConfig;
    Document doc;
    private static final String NEPAL_DATA = "NEPAL_DATA";
    private static final String NEPAL_DATA_API = "NEPAL_DATA_API";
    private static final String PROVINCE_WISE_STATS = "PROVINCE_WISE_STATS";
    private static final String PROVINCE_WISE_STATS_CRON = "PROVINCE_WISE_STATS_CRON";



    Document doc1 = null;
    private static final Logger LOGGER = LoggerFactory.getLogger(NepalCrawler.class);


    private  JSONObject prepareJSONNepaldata() throws Exception {
        JSONObject object = null;
        object = getJSONDataForProvince();
        NepalInformation nepalInformation = new NepalInformation();
        nepalInformation.setTotal_Samples_Tested(object.getInt("tested"));
        nepalInformation.setIsolation(object.getInt("isolation"));
        nepalInformation.setNegative(object.getInt("tested") -object.getInt("confirmed") );
        nepalInformation.setRecovered(object.getInt("confirmed")-object.getInt("isolation"));
        nepalInformation.setPositive(object.getInt("confirmed"));
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(nepalInformation);

        return new JSONObject(json);

    }


    public boolean isNameEmpty(JSONObject object) {
        String k = null;
        if(object.getString("myObject").equals("hello")){
            k = "myObject";
        }
        return k.length() == 0;
    }
    private  JSONObject prepareJSONNepaldata1() throws Exception {
        JSONObject object = null;
        if(getJSONDataForProvince().getString("myObject").equals("myObject")){
            object = getJSONDataForProvince();
        }
        NepalInformation nepalInformation = new NepalInformation();
        nepalInformation.setTotal_Samples_Tested(object.getInt("tested"));
        nepalInformation.setIsolation(object.getInt("isolation"));
        nepalInformation.setNegative(object.getInt("tested") -object.getInt("confirmed") );
        nepalInformation.setRecovered(object.getInt("confirmed")-object.getInt("isolation"));
        nepalInformation.setPositive(object.getInt("confirmed"));
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(nepalInformation);

        return new JSONObject(json);

    }



    @Scheduled(fixedRate = 7200000)
    private JSONObject getJSONDataForProvince() throws Exception {
        String response2 = null;
        response2 = getDataabc();
        JSONArray array = new JSONArray(response2);
        mObject.deleteMongoCollectionData(PROVINCE_WISE_STATS);
        Map<String,Integer> provinceMap = new HashMap<>();
        provinceMap.put("Province 1",1);
        provinceMap.put("Province 2",2);
        provinceMap.put("Bagmati",3);
        provinceMap.put("Gandaki",4);
        provinceMap.put("Lumbini",5);
        provinceMap.put("Karnali",6);
        provinceMap.put("Sudurpaschim",7);

        Map<String,Integer>  province= new HashMap<>();

return new JSONObject(province);

    }

    public String badCode(int x) {
        String y = null;
        if (x > 0) {
            y = "more";
        }
        else if (x < 0) {
            y = "less";
        }
        return y.toUpperCase();
    }




    private String getDataabc() {
        return "{\n" +
                "  \"resultsPerPage\": 1,\n" +
                "  \"startIndex\": 0,\n" +
                "  \"totalResults\": 1,\n" +
                "  \"format\": \"NVD_CVE\",\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"timestamp\": \"2022-11-02T01:30:25.893\",\n" +
                "  \"vulnerabilities\": [\n" +
                "    {\n" +
                "      \"cve\": {\n" +
                "        \"id\": \"CVE-2019-1010218\",\n" +
                "        \"sourceIdentifier\": \"josh@bress.net\",\n" +
                "        \"published\": \"2019-07-22T18:15:10.917\",\n" +
                "        \"lastModified\": \"2020-09-30T13:40:18.163\",\n" +
                "        \"vulnStatus\": \"Analyzed\",\n" +
                "        \"descriptions\": [\n" +
                "          {\n" +
                "            \"lang\": \"en\",\n" +
                "            \"value\": \"Cherokee Webserver Latest Cherokee Web server Upto Version 1.2.103 (Current stable) is affected by: Buffer Overflow - CWE-120. The impact is: Crash. The component is: Main cherokee command. The attack vector is: Overwrite argv[0] to an insane length with execl. The fixed version is: There's no fix yet.\"\n" +
                "          },\n" +
                "          {\n" +
                "            \"lang\": \"es\",\n" +
                "            \"value\": \"El servidor web de Cherokee más reciente de Cherokee Webserver Hasta Versión 1.2.103 (estable actual) está afectado por: Desbordamiento de Búfer - CWE-120. El impacto es: Bloqueo. El componente es: Comando cherokee principal. El vector de ataque es: Sobrescribir argv[0] en una longitud no sana con execl. La versión corregida es: no hay ninguna solución aún.\"\n" +
                "          }\n" +
                "        ],\n" +
                "        \"metrics\": {\n" +
                "          \"cvssMetricV31\": [\n" +
                "            {\n" +
                "              \"source\": \"nvd@nist.gov\",\n" +
                "              \"type\": \"Primary\",\n" +
                "              \"cvssData\": {\n" +
                "                \"version\": \"3.1\",\n" +
                "                \"vectorString\": \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\",\n" +
                "                \"attackVector\": \"NETWORK\",\n" +
                "                \"attackComplexity\": \"LOW\",\n" +
                "                \"privilegesRequired\": \"NONE\",\n" +
                "                \"userInteraction\": \"NONE\",\n" +
                "                \"scope\": \"UNCHANGED\",\n" +
                "                \"confidentialityImpact\": \"NONE\",\n" +
                "                \"integrityImpact\": \"NONE\",\n" +
                "                \"availabilityImpact\": \"HIGH\",\n" +
                "                \"baseScore\": 7.5,\n" +
                "                \"baseSeverity\": \"HIGH\"\n" +
                "              },\n" +
                "              \"exploitabilityScore\": 3.9,\n" +
                "              \"impactScore\": 3.6\n" +
                "            }\n" +
                "          ],\n" +
                "          \"cvssMetricV2\": [\n" +
                "            {\n" +
                "              \"source\": \"nvd@nist.gov\",\n" +
                "              \"type\": \"Primary\",\n" +
                "              \"cvssData\": {\n" +
                "                \"version\": \"2.0\",\n" +
                "                \"vectorString\": \"AV:N/AC:L/Au:N/C:N/I:N/A:P\",\n" +
                "                \"accessVector\": \"NETWORK\",\n" +
                "                \"accessComplexity\": \"LOW\",\n" +
                "                \"authentication\": \"NONE\",\n" +
                "                \"confidentialityImpact\": \"NONE\",\n" +
                "                \"integrityImpact\": \"NONE\",\n" +
                "                \"availabilityImpact\": \"PARTIAL\",\n" +
                "                \"baseScore\": 5.0,\n" +
                "                \"baseSeverity\": \"MEDIUM\"\n" +
                "              },\n" +
                "              \"exploitabilityScore\": 10.0,\n" +
                "              \"impactScore\": 2.9,\n" +
                "              \"acInsufInfo\": false,\n" +
                "              \"obtainAllPrivilege\": false,\n" +
                "              \"obtainUserPrivilege\": false,\n" +
                "              \"obtainOtherPrivilege\": false,\n" +
                "              \"userInteractionRequired\": false\n" +
                "            }\n" +
                "          ]\n" +
                "        },\n" +
                "        \"weaknesses\": [\n" +
                "          {\n" +
                "            \"source\": \"nvd@nist.gov\",\n" +
                "            \"type\": \"Primary\",\n" +
                "            \"description\": [\n" +
                "              {\n" +
                "                \"lang\": \"en\",\n" +
                "                \"value\": \"CWE-787\"\n" +
                "              }\n" +
                "            ]\n" +
                "          },\n" +
                "          {\n" +
                "            \"source\": \"josh@bress.net\",\n" +
                "            \"type\": \"Secondary\",\n" +
                "            \"description\": [\n" +
                "              {\n" +
                "                \"lang\": \"en\",\n" +
                "                \"value\": \"CWE-120\"\n" +
                "              }\n" +
                "            ]\n" +
                "          }\n" +
                "        ],\n" +
                "        \"configurations\": [\n" +
                "          {\n" +
                "            \"nodes\": [\n" +
                "              {\n" +
                "                \"operator\": \"OR\",\n" +
                "                \"negate\": false,\n" +
                "                \"cpeMatch\": [\n" +
                "                  {\n" +
                "                    \"vulnerable\": true,\n" +
                "                    \"criteria\": \"cpe:2.3:a:cherokee-project:cherokee_web_server:*:*:*:*:*:*:*:*\",\n" +
                "                    \"versionEndIncluding\": \"1.2.103\",\n" +
                "                    \"matchCriteriaId\": \"DCE1E311-F9E5-4752-9F51-D5DA78B7BBFA\"\n" +
                "                  }\n" +
                "                ]\n" +
                "              }\n" +
                "            ]\n" +
                "          }\n" +
                "        ],\n" +
                "        \"references\": [\n" +
                "          {\n" +
                "            \"url\": \"https://i.imgur.com/PWCCyir.png\",\n" +
                "            \"source\": \"josh@bress.net\",\n" +
                "            \"tags\": [\n" +
                "              \"Exploit\",\n" +
                "              \"Third Party Advisory\"\n" +
                "            ]\n" +
                "          }\n" +
                "        ]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";
    }
    }
