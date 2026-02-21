package ahodanenok.jose.common;

import java.util.Map;

public interface JsonParser {

    Map<String, Object> parse(String json);
}
