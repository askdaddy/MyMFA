import { NativeModule, requireNativeModule } from 'expo'

declare class MymfaNativeModule extends NativeModule<Record<string, never>> {
  moduleVersion(): string
}

export default requireNativeModule<MymfaNativeModule>('MymfaNative')
