package ahodanenok.jose.jws;

import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import ahodanenok.jose.common.JsonConverter;
import ahodanenok.jose.common.JsonParser;

class JacksonJson implements JsonConverter, JsonParser {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public String convert(Object obj) {
        try {
            return mapper.writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Map<String, Object> parse(String json) {
        try {
            return mapper.readValue(json, Map.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
