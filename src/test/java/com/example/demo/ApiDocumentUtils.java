package com.example.demo;

import org.springframework.restdocs.operation.preprocess.OperationRequestPreprocessor;
import org.springframework.restdocs.operation.preprocess.OperationResponsePreprocessor;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.payload.JsonFieldType;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;

public class ApiDocumentUtils {
    public static OperationRequestPreprocessor getDocumentRequest() {
        return preprocessRequest(
                modifyUris()
                        .scheme("https")
                        .host("api.eventu.com")
                        .removePort(),
                prettyPrint());
    }

    public static OperationResponsePreprocessor getDocumentResponse() {
        return preprocessResponse(prettyPrint());
    }

    public static FieldDescriptor[] getCommonResponseFields() {
        return new FieldDescriptor[] {
                fieldWithPath("code").type(JsonFieldType.STRING).description("응답 코드"),
                fieldWithPath("messages").type(JsonFieldType.ARRAY).description("응답 메시지 배열"),
        };
    }

    public static class DuResponseFieldsInitializer {
        private List<FieldDescriptor> descriptors;

        public DuResponseFieldsInitializer() {
            this.descriptors = new ArrayList<>();
            this.descriptors.add(fieldWithPath("code").type(JsonFieldType.STRING).description("응답 코드"));
            this.descriptors.add(fieldWithPath("messages").type(JsonFieldType.ARRAY).description("응답 메시지 배열"));
        }

        public List<FieldDescriptor> initialize() {
            return this.descriptors;
        }

        public DuResponseFieldsInitializer setField(String path, JsonFieldType fieldType, String description, Boolean required) {
            if (required) {
                this.descriptors.add(fieldWithPath("result." + path).type(fieldType).description(description));
            } else {
                this.descriptors.add(fieldWithPath("result." + path).type(fieldType).description(description).optional());
            }

            return this;
        }
    }
}
