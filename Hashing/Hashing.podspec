Pod::Spec.new do |spec|
    spec.name                     = 'Hashing'
    spec.version                  = '1.0.0-alpha'
    spec.homepage                 = ''
    spec.source                   = { :http=> ''}
    spec.authors                  = 'IOG'
    spec.license                  = ''
    spec.summary                  = 'Apollo Hashing is a Hashing library containing MD2, MD4, MD5, SHA, SHA-2, SHA-3, Blake, Blake2b, Blake2s and Blake3'
    spec.vendored_frameworks      = 'build/cocoapods/framework/ApolloHashing.framework'
    spec.libraries                = 'c++'
    spec.ios.deployment_target = '13.0'
                
                
    spec.pod_target_xcconfig = {
        'KOTLIN_PROJECT_PATH' => ':Hashing',
        'PRODUCT_MODULE_NAME' => 'ApolloHashing',
    }
                
    spec.script_phases = [
        {
            :name => 'Build Hashing',
            :execution_position => :before_compile,
            :shell_path => '/bin/sh',
            :script => <<-SCRIPT
                if [ "YES" = "$COCOAPODS_SKIP_KOTLIN_BUILD" ]; then
                  echo "Skipping Gradle build task invocation due to COCOAPODS_SKIP_KOTLIN_BUILD environment variable set to \"YES\""
                  exit 0
                fi
                set -ev
                REPO_ROOT="$PODS_TARGET_SRCROOT"
                "$REPO_ROOT/../gradlew" -p "$REPO_ROOT" $KOTLIN_PROJECT_PATH:syncFramework \
                    -Pkotlin.native.cocoapods.platform=$PLATFORM_NAME \
                    -Pkotlin.native.cocoapods.archs="$ARCHS" \
                    -Pkotlin.native.cocoapods.configuration="$CONFIGURATION"
            SCRIPT
        }
    ]
                
end