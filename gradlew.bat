@echo off
:: Gradle wrapper for Windows
set DIR=%~dp0
set APP_BASE_NAME=%~n0
set APP_HOME=%DIR%

set DEFAULT_JVM_OPTS=

set CLASSPATH=%APP_HOME%\gradle\wrapper\gradle-wrapper.jar

if exist "%CLASSPATH%" goto execute
echo Gradle wrapper JAR not found at %CLASSPATH%.
echo You can install Gradle locally and run: gradle wrapper --gradle-version 8.7
goto end

:execute
@rem Setup the command line
set CMD_LINE_ARGS=%*

"%JAVA_HOME%\bin\java.exe" %DEFAULT_JVM_OPTS% -classpath "%CLASSPATH%" org.gradle.wrapper.GradleWrapperMain %CMD_LINE_ARGS%

:end
