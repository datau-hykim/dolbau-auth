FROM gradle:8-jdk17-alpine

WORKDIR /app
COPY ./ ./
RUN gradle clean build --no-daemon -x test -x asciidoctor

CMD java -jar build/libs/*.jar
