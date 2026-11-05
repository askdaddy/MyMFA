import { StyleSheet, Text, View } from 'react-native'

import MymfaNativeModule from './modules/mymfa-native/src/MymfaNativeModule'

export default function App() {
  return (
    <View style={styles.container}>
      <Text>MyMFA</Text>
      <Text>原生模块骨架：{MymfaNativeModule.moduleVersion()}</Text>
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
})
